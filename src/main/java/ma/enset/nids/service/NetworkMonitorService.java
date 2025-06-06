package ma.enset.nids.service;

import ma.enset.nids.model.NetworkPacket;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

public class NetworkMonitorService {
    private static final Logger logger = Logger.getLogger(NetworkMonitorService.class.getName());
    private PcapHandle handle;
    private List<PcapNetworkInterface> networkInterfaces;
    private final Map<String, List<Long>> connectionAttempts;
    private final Map<String, AtomicInteger> packetCounter;
    private final Map<String, AtomicLong> trafficByIP;
    private final Map<Integer, AtomicInteger> portActivityCounter;
    private final Set<String> blacklistedIPs;
    
    // Seuils de détection optimisés
    private static final int DOS_THRESHOLD = 50; // Paquets par seconde
    private static final int PORT_SCAN_THRESHOLD = 15; // Ports uniques en 5 secondes
    private static final int SYN_FLOOD_THRESHOLD = 100; // SYN par seconde
    private static final int DDOS_PACKET_THRESHOLD = 1000; // Paquets par seconde pour DDoS
    private static final int DDOS_TIME_WINDOW = 1000; // Fenêtre de temps en ms pour DDoS
    private static final int TRAFFIC_BURST_THRESHOLD = 1000000; // 1MB/s
    private static final int SUSPICIOUS_PORT_THRESHOLD = 20; // Connexions par port
    private static final int FAILED_AUTH_THRESHOLD = 5; // Tentatives d'authentification échouées
    private static final int PING_FLOOD_THRESHOLD = 50; // ICMP par seconde
    private static final int MAX_PACKET_HISTORY = 10000; // Nombre maximum de paquets en mémoire
    private static final int CLEANUP_INTERVAL = 30000; // Intervalle de nettoyage en ms (30s)
    private static final Set<Integer> SUSPICIOUS_PORTS = new HashSet<>(Arrays.asList(
        22, 23, 3389, 445, 135, 137, 138, 139, 1433, 3306, 5432 // Ports sensibles
    ));

    // Statistiques globales
    private final AtomicLong totalPackets;
    private final AtomicLong totalTraffic;
    private final AtomicInteger activeConnections;
    private final AtomicInteger detectedIntrusions;

    private final Map<String, List<Long>> synTimestamps = new ConcurrentHashMap<>();
    private final Map<String, Set<Integer>> portScanTracker = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> icmpTimestamps = new ConcurrentHashMap<>();
    private final Map<String, Integer> failedAuthAttempts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastCleanupTime = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> ddosTracker = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> ddosPacketCounter = new ConcurrentHashMap<>();

    private static final int ALERT_COOLDOWN = 5000; // 5 secondes entre les alertes du même type
    private final Map<String, Long> lastAlertTime = new ConcurrentHashMap<>();
    private final Map<String, String> currentAttackType = new ConcurrentHashMap<>();

    public NetworkMonitorService() throws PcapNativeException {
        this.connectionAttempts = new ConcurrentHashMap<>();
        this.packetCounter = new ConcurrentHashMap<>();
        this.trafficByIP = new ConcurrentHashMap<>();
        this.portActivityCounter = new ConcurrentHashMap<>();
        this.blacklistedIPs = Collections.synchronizedSet(new HashSet<>());
        
        this.totalPackets = new AtomicLong(0);
        this.totalTraffic = new AtomicLong(0);
        this.activeConnections = new AtomicInteger(0);
        this.detectedIntrusions = new AtomicInteger(0);
        
        // Initialiser la liste des interfaces réseau
        this.networkInterfaces = Pcaps.findAllDevs();
    }

    public List<String> getNetworkInterfacesNames() {
        List<String> interfaceNames = new ArrayList<>();
        for (PcapNetworkInterface nif : networkInterfaces) {
            String description = nif.getDescription();
            String name = nif.getName();
            // Ajouter une description plus détaillée de l'interface
            interfaceNames.add(String.format("%s (%s)", 
                description != null ? description : "Unknown", 
                name != null ? name : "No name"));
        }
        return interfaceNames;
    }

    public void startCapture(int selectedInterfaceIndex) throws PcapNativeException {
        if (selectedInterfaceIndex < 0 || selectedInterfaceIndex >= networkInterfaces.size()) {
            throw new IllegalArgumentException("Invalid interface index");
        }

        PcapNetworkInterface nif = networkInterfaces.get(selectedInterfaceIndex);
        if (nif == null) {
            throw new PcapNativeException("No suitable network interface available");
        }

        logger.info("Selected interface: " + nif.getDescription());

        // Fermer l'ancien handle s'il existe
        if (handle != null && handle.isOpen()) {
            handle.close();
        }

        // Ouvrir le nouveau handle
        handle = nif.openLive(
            65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
            1000
        );
    }

    public NetworkPacket capturePacket() throws NotOpenException {
        if (handle == null || !handle.isOpen()) {
            throw new NotOpenException("Pcap handle is not open");
        }

        Packet packet = handle.getNextPacket();
        if (packet == null) {
            return null;
        }

        NetworkPacket networkPacket = new NetworkPacket(packet, true);
        analyzePacket(networkPacket, packet);
        return networkPacket;
    }

    private void analyzePacket(NetworkPacket networkPacket, Packet rawPacket) {
        String sourceIP = networkPacket.getSourceIP();
        String destIP = networkPacket.getDestinationIP();
        
        if (sourceIP == null || destIP == null) {
            return;
        }

        long currentTime = System.currentTimeMillis();
        cleanupOldData(currentTime);

        // Mise à jour des statistiques globales
        totalPackets.incrementAndGet();
        totalTraffic.addAndGet(networkPacket.getSize());
        
        // Analyse du trafic par IP
        updateTrafficStatistics(sourceIP, networkPacket.getSize());
        
        // Détection des attaques
        detectDDoSAttack(networkPacket, sourceIP, currentTime);
        detectDoSAttack(networkPacket, sourceIP, currentTime);
        detectPortScanning(networkPacket, sourceIP, destIP, currentTime);
        detectSynFlood(networkPacket, rawPacket, sourceIP, currentTime);
        detectTrafficBurst(sourceIP);
        detectSuspiciousPortActivity(networkPacket);
        detectPingFlood(rawPacket, sourceIP, currentTime);
        detectBruteForceAttempts(networkPacket, rawPacket, sourceIP);
    }
    
    private void updateTrafficStatistics(String ip, long size) {
        trafficByIP.computeIfAbsent(ip, k -> new AtomicLong(0))
                   .addAndGet(size);
    }
    
    private void detectDDoSAttack(NetworkPacket packet, String sourceIP, long currentTime) {
        // Obtenir ou créer la liste des timestamps pour cette IP
        List<Long> timestamps = ddosTracker.computeIfAbsent(sourceIP, k -> new ArrayList<>());
        timestamps.add(currentTime);

        // Supprimer les timestamps plus vieux que la fenêtre de temps
        timestamps.removeIf(ts -> (currentTime - ts) > DDOS_TIME_WINDOW);

        // Calculer le taux de paquets par seconde sur la fenêtre de temps
        double packetsPerSecond = (timestamps.size() * 1000.0) / DDOS_TIME_WINDOW;

        // Vérifier si c'est une attaque DDoS
        if (packetsPerSecond > DDOS_PACKET_THRESHOLD) {
            // Vérifier les caractéristiques supplémentaires
            boolean hasHighTraffic = trafficByIP.get(sourceIP) != null && 
                                   trafficByIP.get(sourceIP).get() > TRAFFIC_BURST_THRESHOLD;
            boolean hasSynFlood = synTimestamps.containsKey(sourceIP) && 
                                synTimestamps.get(sourceIP).size() > SYN_FLOOD_THRESHOLD;
            
            // Pour une attaque sur un seul port, vérifier l'intensité
            AtomicInteger portCount = portActivityCounter.get(packet.getDestinationPort());
            boolean hasHighPortActivity = portCount != null && portCount.get() > SUSPICIOUS_PORT_THRESHOLD;

            // Détecter l'attaque si les conditions sont remplies
            if (packetsPerSecond > DDOS_PACKET_THRESHOLD * 2 || // Taux très élevé
                (hasHighTraffic && hasSynFlood) || // DDoS classique
                (hasHighTraffic && hasHighPortActivity && packetsPerSecond > DDOS_PACKET_THRESHOLD * 1.5)) { // DDoS ciblé
                
                if (shouldGenerateAlert(sourceIP, "DDoS", currentTime)) {
                    packet.setIntrusion(true);
                    packet.setIntrusionType("DDoS Attack");
                    markIntrusion(packet, String.format("DDoS Attack - Rate: %.2f pkts/s, Traffic: %.2f MB/s, SYN Flood: %b", 
                        packetsPerSecond,
                        trafficByIP.get(sourceIP).get() / 1000000.0,
                        hasSynFlood), 
                        sourceIP);
                    blacklistedIPs.add(sourceIP);
                }
                
                // Réinitialiser les compteurs
                timestamps.clear();
                if (portCount != null) portCount.set(0);
            }
        }
    }
    
    private void detectDoSAttack(NetworkPacket packet, String sourceIP, long currentTime) {
        List<Long> timestamps = connectionAttempts.computeIfAbsent(sourceIP, k -> new ArrayList<>());
        timestamps.add(currentTime);
        
        // Ne garder que les timestamps des dernières 1 seconde
        timestamps.removeIf(ts -> (currentTime - ts) > 1000);
        
        if (timestamps.size() > DOS_THRESHOLD && !packet.getIntrusionType().equals("DDoS Attack")) {
            markIntrusion(packet, "DoS Attack (High packet rate)", sourceIP);
            blacklistedIPs.add(sourceIP);
            timestamps.clear();
        }
    }
    
    private void detectPortScanning(NetworkPacket packet, String sourceIP, String destIP, long currentTime) {
        String key = sourceIP + "-" + destIP;
        Set<Integer> targetPorts = portScanTracker.computeIfAbsent(key, k -> new HashSet<>());
        targetPorts.add(packet.getDestinationPort());
        
        // Vérifier les ports scannés dans les 5 dernières secondes
        if (targetPorts.size() > PORT_SCAN_THRESHOLD) {
            markIntrusion(packet, "Port Scanning (Multiple ports)", sourceIP);
            portScanTracker.remove(key);
        }
    }
    
    private void detectSynFlood(NetworkPacket networkPacket, Packet rawPacket, String sourceIP, long currentTime) {
        TcpPacket tcpPacket = rawPacket.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
            List<Long> synTimestampsList = synTimestamps.computeIfAbsent(sourceIP, k -> new ArrayList<>());
            synTimestampsList.add(currentTime);
            
            // Ne garder que les SYN des dernières 1 seconde
            synTimestampsList.removeIf(ts -> (currentTime - ts) > 1000);
            
            if (synTimestampsList.size() > SYN_FLOOD_THRESHOLD) {
                markIntrusion(networkPacket, "SYN Flood Attack", sourceIP);
                synTimestamps.remove(sourceIP);
            }
        }
    }
    
    private void detectPingFlood(Packet rawPacket, String sourceIP, long currentTime) {
        IcmpV4CommonPacket icmpPacket = rawPacket.get(IcmpV4CommonPacket.class);
        if (icmpPacket != null) {
            List<Long> icmpTimestampsList = icmpTimestamps.computeIfAbsent(sourceIP, k -> new ArrayList<>());
            icmpTimestampsList.add(currentTime);
            
            // Ne garder que les ICMP des dernières 1 seconde
            icmpTimestampsList.removeIf(ts -> (currentTime - ts) > 1000);
            
            if (icmpTimestampsList.size() > PING_FLOOD_THRESHOLD) {
                NetworkPacket packet = new NetworkPacket(rawPacket, true);
                markIntrusion(packet, "ICMP Flood Attack", sourceIP);
                icmpTimestamps.remove(sourceIP);
            }
        }
    }
    
    private void detectBruteForceAttempts(NetworkPacket packet, Packet rawPacket, String sourceIP) {
        TcpPacket tcpPacket = rawPacket.get(TcpPacket.class);
        if (tcpPacket != null && SUSPICIOUS_PORTS.contains(packet.getDestinationPort())) {
            int attempts = failedAuthAttempts.getOrDefault(sourceIP, 0) + 1;
            failedAuthAttempts.put(sourceIP, attempts);
            
            if (attempts > FAILED_AUTH_THRESHOLD) {
                markIntrusion(packet, "Possible Brute Force Attack", sourceIP);
                failedAuthAttempts.remove(sourceIP);
            }
        }
    }
    
    private void detectTrafficBurst(String sourceIP) {
        AtomicLong traffic = trafficByIP.get(sourceIP);
        if (traffic != null && traffic.get() > TRAFFIC_BURST_THRESHOLD) {
            logger.warning("Traffic burst detected from IP: " + sourceIP);
            traffic.set(0);
        }
    }
    
    private void detectSuspiciousPortActivity(NetworkPacket packet) {
        int port = packet.getDestinationPort();
        if (port > 0) {
            portActivityCounter.computeIfAbsent(port, k -> new AtomicInteger(0));
            int count = portActivityCounter.get(port).incrementAndGet();
            
            if (count > SUSPICIOUS_PORT_THRESHOLD) {
                markIntrusion(packet, "Suspicious Port Activity", null);
                portActivityCounter.get(port).set(0);
            }
        }
    }

    private boolean shouldGenerateAlert(String sourceIP, String attackType, long currentTime) {
        String key = sourceIP + "-" + attackType;
        Long lastTime = lastAlertTime.get(key);
        
        if (lastTime == null || (currentTime - lastTime) > ALERT_COOLDOWN) {
            lastAlertTime.put(key, currentTime);
            currentAttackType.put(sourceIP, attackType);
            return true;
        }
        return false;
    }

    private void markIntrusion(NetworkPacket packet, String type, String sourceIP) {
        long currentTime = System.currentTimeMillis();
        
        // Si l'IP est déjà sous attaque d'un type plus critique, ignorer les alertes moins critiques
        String currentType = currentAttackType.get(sourceIP);
        if (currentType != null) {
            if ((currentType.contains("DDoS") && !type.contains("DDoS")) ||
                (currentType.contains("DoS") && !type.contains("DoS") && !type.contains("DDoS"))) {
                return;
            }
        }
        
        // Vérifier si on doit générer une nouvelle alerte
        if (shouldGenerateAlert(sourceIP, type, currentTime)) {
            packet.setIntrusion(true);
            packet.setIntrusionType(type);
            detectedIntrusions.incrementAndGet();
            
            if (sourceIP != null) {
                logger.warning(type + " detected from IP: " + sourceIP);
            }
        }
    }

    private void cleanupOldData(long currentTime) {
        // Ne nettoyer que toutes les 30 secondes
        lastCleanupTime.computeIfAbsent("cleanup", k -> currentTime);
        if (currentTime - lastCleanupTime.get("cleanup") > CLEANUP_INTERVAL) {
            // Nettoyage des anciennes données
            synTimestamps.entrySet().removeIf(entry -> 
                entry.getValue().stream().allMatch(ts -> (currentTime - ts) > 5000));
            portScanTracker.entrySet().removeIf(entry -> 
                !entry.getValue().isEmpty() && (currentTime - lastCleanupTime.get("cleanup")) > 5000);
            icmpTimestamps.entrySet().removeIf(entry -> 
                entry.getValue().stream().allMatch(ts -> (currentTime - ts) > 5000));
            failedAuthAttempts.entrySet().removeIf(entry -> 
                (currentTime - lastCleanupTime.get("cleanup")) > 300000);
            
            // Nettoyer les anciennes alertes
            lastAlertTime.entrySet().removeIf(entry -> (currentTime - entry.getValue()) > ALERT_COOLDOWN);
            currentAttackType.entrySet().removeIf(entry -> 
                !lastAlertTime.containsKey(entry.getKey() + "-" + entry.getValue()));
            
            // Nettoyer les statistiques de trafic
            trafficByIP.entrySet().removeIf(entry -> entry.getValue().get() == 0);
            portActivityCounter.entrySet().removeIf(entry -> entry.getValue().get() == 0);
            
            lastCleanupTime.put("cleanup", currentTime);
        }
    }

    // Getters pour les statistiques
    public int getActiveConnections() {
        return activeConnections.get();
    }
    
    public long getTotalPackets() {
        return totalPackets.get();
    }
    
    public long getTotalTraffic() {
        return totalTraffic.get();
    }
    
    public int getDetectedIntrusions() {
        return detectedIntrusions.get();
    }

    public Map<String, Long> getTrafficByIP() {
        Map<String, Long> traffic = new HashMap<>();
        trafficByIP.forEach((ip, count) -> traffic.put(ip, count.get()));
        return traffic;
    }
    
    public Set<String> getBlacklistedIPs() {
        return new HashSet<>(blacklistedIPs);
    }

    public void resetStatistics() {
        // Réinitialiser les compteurs atomiques
        totalPackets.set(0);
        totalTraffic.set(0);
        activeConnections.set(0);
        detectedIntrusions.set(0);
        
        // Réinitialiser les maps
        connectionAttempts.clear();
        packetCounter.clear();
        trafficByIP.clear();
        portActivityCounter.clear();
        blacklistedIPs.clear();
        lastAlertTime.clear();
        currentAttackType.clear();
    }

    public void close() {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }
} 