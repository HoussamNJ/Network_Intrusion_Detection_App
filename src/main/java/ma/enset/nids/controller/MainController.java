package ma.enset.nids.controller;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import ma.enset.nids.model.NetworkPacket;
import ma.enset.nids.service.NetworkMonitorService;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.LinkedList;
import java.io.File;

public class MainController {
    private static final Logger logger = Logger.getLogger(MainController.class.getName());
    
    @FXML private Label activeConnectionsLabel;
    @FXML private Label totalPacketsLabel;
    @FXML private Label intrusionsLabel;
    @FXML private Label totalTrafficLabel;
    @FXML private Label statusLabel;
    @FXML private Label captureTimeLabel;
    
    @FXML private Button startButton;
    @FXML private Button stopButton;
    
    @FXML private ComboBox<String> interfaceSelector;
    @FXML private ComboBox<String> protocolFilter;
    @FXML private TextField ipFilter;
    @FXML private TextField portFilter;
    
    @FXML private LineChart<Number, Number> trafficChart;
    @FXML private TableView<NetworkPacket> packetsTable;
    @FXML private TextArea alertsTextArea;
    
    private volatile boolean isCapturing = false;
    private NetworkMonitorService monitorService;
    private Timer updateTimer;
    private LocalDateTime captureStartTime;
    private final ObservableList<NetworkPacket> packets = FXCollections.observableArrayList();
    private XYChart.Series<Number, Number> trafficSeries;
    private long chartStartTime;
    private ExecutorService executorService;
    
    private static final int WINDOW_SIZE = 30; // Taille de la fenêtre glissante en secondes
    private static final int UPDATE_INTERVAL = 100; // Intervalle de mise à jour en millisecondes
    private final LinkedList<Long> packetTimestamps = new LinkedList<>();
    
    @FXML
    public void initialize() {
        try {
            setupUI();
            monitorService = new NetworkMonitorService();
            setupInterfaceSelector();
            setupProtocolFilter();
            executorService = Executors.newSingleThreadExecutor();
            
            // Configuration initiale du graphique
            NumberAxis xAxis = (NumberAxis) trafficChart.getXAxis();
            xAxis.setLabel("Temps (s)");
            xAxis.setAutoRanging(true);
            xAxis.setForceZeroInRange(true);
            
            NumberAxis yAxis = (NumberAxis) trafficChart.getYAxis();
            yAxis.setLabel("Paquets/s");
            yAxis.setAutoRanging(true);
            yAxis.setForceZeroInRange(true);
            
            trafficSeries = new XYChart.Series<>();
            trafficSeries.setName("Trafic réseau");
            trafficChart.getData().add(trafficSeries);
            
        } catch (Exception e) {
            logger.severe("Failed to initialize: " + e.getMessage());
            showError("Erreur d'initialisation", e.getMessage());
        }
    }
    
    private void setupUI() {
        stopButton.setDisable(true);
        packetsTable.setItems(packets);
        
        // Configuration des colonnes
        TableColumn<NetworkPacket, LocalDateTime> timestampCol = new TableColumn<>("Horodatage");
        timestampCol.setCellValueFactory(new PropertyValueFactory<>("timestamp"));
        timestampCol.setCellFactory(column -> new TableCell<NetworkPacket, LocalDateTime>() {
            private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SS");
            
            @Override
            protected void updateItem(LocalDateTime item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(item.format(formatter));
                }
            }
        });
        
        TableColumn<NetworkPacket, String> sourceIPCol = new TableColumn<>("IP Source");
        sourceIPCol.setCellValueFactory(new PropertyValueFactory<>("sourceIP"));
        
        TableColumn<NetworkPacket, Integer> sourcePortCol = new TableColumn<>("Port Source");
        sourcePortCol.setCellValueFactory(new PropertyValueFactory<>("sourcePort"));
        
        TableColumn<NetworkPacket, String> destIPCol = new TableColumn<>("IP Destination");
        destIPCol.setCellValueFactory(new PropertyValueFactory<>("destinationIP"));
        
        TableColumn<NetworkPacket, Integer> destPortCol = new TableColumn<>("Port Destination");
        destPortCol.setCellValueFactory(new PropertyValueFactory<>("destinationPort"));
        
        TableColumn<NetworkPacket, String> protocolCol = new TableColumn<>("Protocole");
        protocolCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        
        TableColumn<NetworkPacket, Long> sizeCol = new TableColumn<>("Taille (Ko)");
        sizeCol.setCellValueFactory(new PropertyValueFactory<>("size"));
        sizeCol.setCellFactory(column -> new TableCell<NetworkPacket, Long>() {
            @Override
            protected void updateItem(Long item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(String.format("%.2f", item / 1024.0));
                }
            }
        });
        
        TableColumn<NetworkPacket, Boolean> intrusionCol = new TableColumn<>("Intrusion");
        intrusionCol.setCellValueFactory(new PropertyValueFactory<>("intrusion"));
        intrusionCol.setCellFactory(column -> new TableCell<NetworkPacket, Boolean>() {
            @Override
            protected void updateItem(Boolean item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(item ? "⚠️" : "");
                }
            }
        });
        
        packetsTable.getColumns().addAll(
            timestampCol, sourceIPCol, sourcePortCol,
            destIPCol, destPortCol, protocolCol,
            sizeCol, intrusionCol
        );
        
        // Configuration du tableau
        packetsTable.setRowFactory(tv -> {
            TableRow<NetworkPacket> row = new TableRow<NetworkPacket>() {
                @Override
                protected void updateItem(NetworkPacket item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setStyle("");
                    } else if (item.isIntrusion()) {
                        setStyle("-fx-background-color: #ffebee;");
                    } else {
                        setStyle("");
                    }
                }
            };
            return row;
        });
    }
    
    private void setupInterfaceSelector() {
        // Remplir le ComboBox avec les interfaces disponibles
        List<String> interfaces = monitorService.getNetworkInterfacesNames();
        interfaceSelector.getItems().addAll(interfaces);
        
        // Sélectionner la première interface par défaut si disponible
        if (!interfaces.isEmpty()) {
            interfaceSelector.getSelectionModel().selectFirst();
        }
        
        // Gérer l'activation/désactivation du bouton de démarrage
        interfaceSelector.getSelectionModel().selectedIndexProperty().addListener((obs, oldVal, newVal) -> {
            startButton.setDisable(newVal.intValue() == -1);
        });
    }
    
    private void setupProtocolFilter() {
        protocolFilter.getItems().addAll(
            "Tous",
            "TCP",
            "UDP",
            "ICMP",
            "HTTP",
            "HTTPS",
            "DNS"
        );
        protocolFilter.setValue("Tous");
        
        // Ajouter des listeners pour les filtres
        protocolFilter.valueProperty().addListener((obs, oldVal, newVal) -> {
            if (!oldVal.equals(newVal)) {
                filterPackets();
            }
        });
        
        ipFilter.textProperty().addListener((obs, oldVal, newVal) -> {
            if (!oldVal.equals(newVal)) {
                filterPackets();
            }
        });
        
        portFilter.textProperty().addListener((obs, oldVal, newVal) -> {
            if (!oldVal.equals(newVal)) {
                filterPackets();
            }
        });
    }
    
    @FXML
    private void handleStartCapture() {
        if (!isCapturing) {
            try {
                int selectedIndex = interfaceSelector.getSelectionModel().getSelectedIndex();
                if (selectedIndex < 0) {
                    showError("Erreur", "Veuillez sélectionner une interface réseau");
                    return;
                }

                // Démarrer la capture sur l'interface sélectionnée
                monitorService.startCapture(selectedIndex);
                
                isCapturing = true;
                captureStartTime = LocalDateTime.now();
                chartStartTime = System.currentTimeMillis();
                
                startButton.setDisable(true);
                stopButton.setDisable(false);
                interfaceSelector.setDisable(true);
                statusLabel.setText("Capture en cours...");
                
                startUpdateTimer();
                
            } catch (Exception e) {
                logger.severe("Failed to start capture: " + e.getMessage());
                showError("Erreur de capture", e.getMessage());
                
                // Arrêter la capture en cas d'erreur
                isCapturing = false;
                if (updateTimer != null) {
                    updateTimer.cancel();
                }
                startButton.setDisable(false);
                stopButton.setDisable(true);
                interfaceSelector.setDisable(false);
                statusLabel.setText("Capture arrêtée");
            }
        }
    }
    
    @FXML
    private void handleStopCapture() {
        if (isCapturing) {
            isCapturing = false;
            if (updateTimer != null) {
                updateTimer.cancel();
            }
            
            startButton.setDisable(false);
            stopButton.setDisable(true);
            interfaceSelector.setDisable(false);
            statusLabel.setText("Capture arrêtée");
        }
    }
    
    private void startUpdateTimer() {
        updateTimer = new Timer(true);
        updateTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    if (isCapturing) {
                        NetworkPacket packet = monitorService.capturePacket();
                        if (packet != null) {
                            processPacket(packet);
                        }
                    }
                } catch (Exception e) {
                    logger.warning("Error during packet capture: " + e.getMessage());
                }
            }
        }, 0, 10); // Capture toutes les 10ms
    }
    
    private ObservableList<NetworkPacket> allPackets = FXCollections.observableArrayList();
    
    private void filterPackets() {
        packets.clear();
        allPackets.stream()
            .filter(this::matchesFilters)
            .forEach(packets::add);
    }
    
    private void processPacket(NetworkPacket packet) {
        Platform.runLater(() -> {
            updateStatistics();
            
            allPackets.add(0, packet);
            if (allPackets.size() > 1000) {
                allPackets.remove(1000, allPackets.size());
            }
            
            if (matchesFilters(packet)) {
                packets.add(0, packet);
                if (packets.size() > 1000) {
                    packets.remove(1000, packets.size());
                }
            }
            
            updateChart();
            
            if (packet.isIntrusion()) {
                String alert = String.format("[%s] %s détecté - Source: %s, Destination: %s\n",
                    packet.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SS")),
                    packet.getIntrusionType(),
                    packet.getSourceIP(),
                    packet.getDestinationIP()
                );
                alertsTextArea.appendText(alert);
            }
        });
    }
    
    private boolean matchesFilters(NetworkPacket packet) {
        String selectedProtocol = protocolFilter.getValue();
        String ipFilterText = ipFilter.getText().trim();
        String portFilterText = portFilter.getText().trim();
        
        boolean protocolMatch = "Tous".equals(selectedProtocol) || 
                             selectedProtocol.equals(packet.getProtocol());
        boolean ipMatch = ipFilterText.isEmpty() || 
                        packet.getSourceIP().contains(ipFilterText) || 
                        packet.getDestinationIP().contains(ipFilterText);
        boolean portMatch = portFilterText.isEmpty() || 
                          String.valueOf(packet.getSourcePort()).contains(portFilterText) || 
                          String.valueOf(packet.getDestinationPort()).contains(portFilterText);
        
        return protocolMatch && ipMatch && portMatch;
    }
    
    private void updateStatistics() {
        activeConnectionsLabel.setText(String.valueOf(monitorService.getActiveConnections()));
        totalPacketsLabel.setText(String.valueOf(monitorService.getTotalPackets()));
        intrusionsLabel.setText(String.valueOf(monitorService.getDetectedIntrusions()));
        
        long totalTraffic = monitorService.getTotalTraffic();
        String trafficStr = formatTrafficSize(totalTraffic);
        totalTrafficLabel.setText(trafficStr);
        
        Duration duration = Duration.between(captureStartTime, LocalDateTime.now());
        String timeStr = String.format("%02d:%02d:%02d",
            duration.toHours(),
            duration.toMinutesPart(),
            duration.toSecondsPart()
        );
        captureTimeLabel.setText("Temps de capture: " + timeStr);
    }
    
    private void updateChart() {
        long currentTime = System.currentTimeMillis();
        double timeInSeconds = (currentTime - chartStartTime) / 1000.0;
        
        // Ajouter le timestamp du nouveau paquet
        packetTimestamps.addLast(currentTime);
        
        // Supprimer les timestamps plus vieux que WINDOW_SIZE secondes
        while (!packetTimestamps.isEmpty() && 
               (currentTime - packetTimestamps.getFirst()) > WINDOW_SIZE * 1000) {
            packetTimestamps.removeFirst();
        }
        
        // Calculer le taux de paquets par seconde sur la fenêtre glissante
        double packetsPerSecond = (double) packetTimestamps.size() / 
                                (Math.min(WINDOW_SIZE, (currentTime - chartStartTime) / 1000.0));
        
        // Ajouter le nouveau point
        Platform.runLater(() -> {
            trafficSeries.getData().add(new XYChart.Data<>(timeInSeconds, packetsPerSecond));
            
            // Garder seulement les 300 derniers points (10 minutes à raison d'un point toutes les 2 secondes)
            if (trafficSeries.getData().size() > 300) {
                trafficSeries.getData().remove(0);
            }
            
            // Ajuster les axes si nécessaire
            NumberAxis xAxis = (NumberAxis) trafficChart.getXAxis();
            NumberAxis yAxis = (NumberAxis) trafficChart.getYAxis();
            
            // Ajuster l'axe X pour montrer les 30 dernières secondes
            xAxis.setLowerBound(Math.max(0, timeInSeconds - WINDOW_SIZE));
            xAxis.setUpperBound(timeInSeconds);
            
            // Ajuster l'axe Y pour avoir une marge de 20% au-dessus du maximum
            double maxY = packetsPerSecond * 1.2;
            yAxis.setUpperBound(Math.max(10, maxY));
        });
    }
    
    private void resetChart() {
        Platform.runLater(() -> {
            // Vider la série mais garder la référence
            trafficSeries.getData().clear();
            
            // Réinitialiser le temps de départ
            chartStartTime = System.currentTimeMillis();
            
            // Vider la liste des timestamps
            packetTimestamps.clear();
            
            // Réinitialiser les axes
            NumberAxis xAxis = (NumberAxis) trafficChart.getXAxis();
            NumberAxis yAxis = (NumberAxis) trafficChart.getYAxis();
            
            xAxis.setLowerBound(0);
            xAxis.setUpperBound(WINDOW_SIZE);
            xAxis.setTickUnit(5);
            
            yAxis.setLowerBound(0);
            yAxis.setUpperBound(10);
            yAxis.setTickUnit(2);
        });
    }
    
    private String formatTrafficSize(long bytes) {
        String[] units = {"B", "KB", "MB", "GB"};
        int unitIndex = 0;
        double size = bytes;
        
        while (size > 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        
        return String.format("%.2f %s", size, units[unitIndex]);
    }
    
    private void resetStatistics() {
        // Réinitialiser les statistiques
        Platform.runLater(() -> {
            activeConnectionsLabel.setText("0");
            totalPacketsLabel.setText("0");
            intrusionsLabel.setText("0");
            totalTrafficLabel.setText("0 B");
            
            // Réinitialiser le service de monitoring
            monitorService.resetStatistics();
            
            // Réinitialiser le temps de capture
            captureStartTime = LocalDateTime.now();
            chartStartTime = System.currentTimeMillis();
            
            // Réinitialiser le graphique
            resetChart();
        });
    }
    
    @FXML
    private void handleApplyFilters() {
        resetStatistics();
        filterPackets();
    }
    
    @FXML
    private void handleResetFilters() {
        protocolFilter.setValue("Tous");
        ipFilter.clear();
        portFilter.clear();
        resetStatistics();
        filterPackets();
        packets.clear();
        packets.addAll(allPackets);
    }
    
    @FXML
    private void handleCopySourceIP() {
        NetworkPacket selectedPacket = packetsTable.getSelectionModel().getSelectedItem();
        if (selectedPacket != null) {
            copyToClipboard(selectedPacket.getSourceIP());
        }
    }
    
    @FXML
    private void handleCopyDestIP() {
        NetworkPacket selectedPacket = packetsTable.getSelectionModel().getSelectedItem();
        if (selectedPacket != null) {
            copyToClipboard(selectedPacket.getDestinationIP());
        }
    }
    
    @FXML
    private void handleShowPacketDetails() {
        NetworkPacket selectedPacket = packetsTable.getSelectionModel().getSelectedItem();
        if (selectedPacket != null) {
            showPacketDetailsDialog(selectedPacket);
        }
    }
    
    @FXML
    private void handleExportSelected() {
        // TODO: Implémenter l'exportation des paquets sélectionnés
    }
    
    @FXML
    private void handleExportAlerts() {
        try {
            // Créer le dossier generated_rapport s'il n'existe pas
            File reportsDir = new File("generated_rapport");
            if (!reportsDir.exists()) {
                reportsDir.mkdir();
            }
            
            // Créer le nom du fichier avec la date et l'heure
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            String fileName = "alerts_" + timestamp + ".txt";
            
            // Chemin complet du fichier dans le dossier generated_rapport
            File reportFile = new File(reportsDir, fileName);
            
            // Créer le fichier et écrire les alertes
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportFile))) {
                writer.write("=== Rapport d'Alertes de Sécurité ===\n");
                writer.write("Date d'export: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "\n");
                writer.write("Nombre total d'intrusions détectées: " + monitorService.getDetectedIntrusions() + "\n\n");
                
                writer.write("=== Détail des Alertes ===\n");
                writer.write(alertsTextArea.getText());
                
                writer.write("\n=== Statistiques ===\n");
                writer.write("Paquets totaux analysés: " + monitorService.getTotalPackets() + "\n");
                writer.write("Trafic total: " + formatTrafficSize(monitorService.getTotalTraffic()) + "\n");
                writer.write("IPs blacklistées: " + String.join(", ", monitorService.getBlacklistedIPs()) + "\n");
            }
            
            // Afficher une confirmation
            showInfo("Export Réussi", 
                    "Les alertes ont été exportées avec succès vers:\n" + reportFile.getAbsolutePath());
            
        } catch (IOException e) {
            showError("Erreur d'Export", 
                     "Impossible d'exporter les alertes: " + e.getMessage());
            logger.severe("Failed to export alerts: " + e.getMessage());
        }
    }
    
    @FXML
    private void handleClearAlerts() {
        alertsTextArea.clear();
    }
    
    private void copyToClipboard(String text) {
        javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
        content.putString(text);
        clipboard.setContent(content);
    }
    
    private void showPacketDetailsDialog(NetworkPacket packet) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Détails du Paquet");
        alert.setHeaderText(null);
        
        TextArea textArea = new TextArea(packet.toString());
        textArea.setEditable(false);
        textArea.setWrapText(true);
        textArea.setPrefRowCount(20);
        textArea.setPrefColumnCount(50);
        
        alert.getDialogPane().setContent(textArea);
        alert.showAndWait();
    }
    
    private void showError(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }
    
    private void showInfo(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }
    
    private void startPacketUpdates() {
        executorService.submit(() -> {
            while (isCapturing && !Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(UPDATE_INTERVAL);
                    Platform.runLater(() -> {
                        try {
                            NetworkPacket packet = monitorService.capturePacket();
                            if (packet != null) {
                                packets.add(0, packet);
                                if (packets.size() > 1000) {
                                    packets.remove(1000);
                                }
                                updateChart();
                            }
                            statusLabel.setText("Packets captured: " + packets.size());
                        } catch (Exception e) {
                            logger.severe("Error updating packet display: " + e.getMessage());
                        }
                    });
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
    }
} 