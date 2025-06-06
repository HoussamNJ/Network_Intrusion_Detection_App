package ma.enset.nids.service;

import ma.enset.nids.model.DetectionRule;
import ma.enset.nids.model.NetworkPacket;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.logging.Logger;

public class IntrusionDetectionSystem {
    private static final Logger logger = Logger.getLogger(IntrusionDetectionSystem.class.getName());
    private static final int MAX_PACKETS_PER_SOURCE = 1000;
    private static final int CLEANUP_INTERVAL_MINUTES = 5;
    private static final double DOS_PACKETS_PER_SECOND = 700.0;
    private static final int PORT_SCAN_UNIQUE_PORTS = 15;
    private static final int PORT_SCAN_TIME_WINDOW = 10;

    private final List<DetectionRule> rules;
    private final Map<String, List<NetworkPacket>> packetsBySource;
    private final Map<String, Set<Integer>> uniquePortsMap;
    private final Map<String, LocalDateTime> lastCleanupTime;
    private Consumer<String> alertCallback;

    public IntrusionDetectionSystem() {
        this.rules = initializeRules();
        this.packetsBySource = new ConcurrentHashMap<>();
        this.uniquePortsMap = new ConcurrentHashMap<>();
        this.lastCleanupTime = new ConcurrentHashMap<>();
    }

    public void setAlertCallback(Consumer<String> callback) {
        this.alertCallback = callback;
    }

    private List<DetectionRule> initializeRules() {
        List<DetectionRule> rules = new ArrayList<>();
        rules.add(new DetectionRule("DoS Detection", DetectionRule.RuleType.DOS_ATTACK, DOS_PACKETS_PER_SECOND, 60));
        rules.add(new DetectionRule("Port Scanning", DetectionRule.RuleType.PORT_SCAN, PORT_SCAN_UNIQUE_PORTS, PORT_SCAN_TIME_WINDOW));
        rules.add(new DetectionRule("Brute Force", DetectionRule.RuleType.BRUTE_FORCE, 5, 300));
        return rules;
    }

    public void analyzePacket(NetworkPacket packet) {
        String sourceIP = packet.getSourceIP();
        String destIP = packet.getDestinationIP();

        // Ignorer les adresses de broadcast et multicast
        if (isIgnoredAddress(sourceIP) || isIgnoredAddress(destIP)) {
            return;
        }

        // Ajouter le paquet à l'historique
        List<NetworkPacket> sourcePackets = packetsBySource.computeIfAbsent(sourceIP, k -> new ArrayList<>());
        sourcePackets.add(packet);

        // Limiter le nombre de paquets stockés par source
        if (sourcePackets.size() > MAX_PACKETS_PER_SOURCE) {
            sourcePackets.remove(0);
        }

        // Analyser les attaques potentielles
        detectDoSAttack(packet, sourcePackets);
        detectPortScanning(packet);
        detectBruteForceAttempt(packet);

        // Nettoyage périodique
        cleanOldPackets(sourceIP);
    }

    private boolean isIgnoredAddress(String ip) {
        return ip == null || ip.endsWith(".255") || ip.endsWith(".0") ||
               ip.startsWith("224.") || ip.startsWith("239.") ||
               ip.equals("127.0.0.1");
    }

    private void detectDoSAttack(NetworkPacket packet, List<NetworkPacket> sourcePackets) {
        String sourceIP = packet.getSourceIP();
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime timeWindow = now.minusSeconds(60);

        long packetsInWindow = sourcePackets.stream()
                .filter(p -> p.getTimestamp().isAfter(timeWindow))
                .count();

        double packetsPerSecond = packetsInWindow / 60.0;

        if (packetsPerSecond > DOS_PACKETS_PER_SECOND) {
            String alert = String.format("DoS Attack detected from IP: %s (%.2f packets/second)", 
                sourceIP, packetsPerSecond);
            sendAlert(alert);
            packet.setIntrusion(true);
            packet.setIntrusionType("DoS Attack");
            logger.warning(alert);
        }
    }

    private void detectPortScanning(NetworkPacket packet) {
        String sourceIP = packet.getSourceIP();
        String destIP = packet.getDestinationIP();
        int destPort = packet.getDestinationPort();

        // Créer une clé unique pour la paire source-destination
        String key = sourceIP + "_" + destIP;
        Set<Integer> uniquePorts = uniquePortsMap.computeIfAbsent(key, k -> new HashSet<>());
        uniquePorts.add(destPort);

        // Vérifier le nombre de ports uniques dans la fenêtre de temps
        if (uniquePorts.size() > PORT_SCAN_UNIQUE_PORTS) {
            String alert = String.format("Port Scanning detected - Source: %s, Target: %s, Unique Ports: %d", 
                sourceIP, destIP, uniquePorts.size());
            sendAlert(alert);
            packet.setIntrusion(true);
            packet.setIntrusionType("Port Scanning");
            logger.warning(alert);
            uniquePorts.clear();
        }
    }

    private void detectBruteForceAttempt(NetworkPacket packet) {
        // Ports sensibles pour la détection de brute force
        Set<Integer> sensitivePorts = new HashSet<>(Arrays.asList(22, 23, 3389, 445));
        
        if (sensitivePorts.contains(packet.getDestinationPort())) {
            String key = packet.getSourceIP() + "_" + packet.getDestinationIP() + "_" + packet.getDestinationPort();
            List<NetworkPacket> attempts = packetsBySource.computeIfAbsent(key, k -> new ArrayList<>());
            attempts.add(packet);

            // Nettoyer les tentatives plus anciennes que 5 minutes
            attempts.removeIf(p -> p.getTimestamp().isBefore(LocalDateTime.now().minusMinutes(5)));

            if (attempts.size() > 5) {
                String alert = String.format("Possible Brute Force Attack - Source: %s, Target: %s:%d", 
                    packet.getSourceIP(), packet.getDestinationIP(), packet.getDestinationPort());
                sendAlert(alert);
                packet.setIntrusion(true);
                packet.setIntrusionType("Brute Force Attempt");
                logger.warning(alert);
                attempts.clear();
            }
        }
    }

    private void cleanOldPackets(String sourceIP) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime lastCleanup = lastCleanupTime.getOrDefault(sourceIP, now.minusMinutes(CLEANUP_INTERVAL_MINUTES + 1));

        if (lastCleanup.plusMinutes(CLEANUP_INTERVAL_MINUTES).isBefore(now)) {
            List<NetworkPacket> packets = packetsBySource.get(sourceIP);
            if (packets != null) {
                packets.removeIf(p -> p.getTimestamp().isBefore(now.minusMinutes(CLEANUP_INTERVAL_MINUTES)));
                if (packets.isEmpty()) {
                    packetsBySource.remove(sourceIP);
                }
            }

            // Nettoyer les ports uniques
            uniquePortsMap.entrySet().removeIf(entry -> {
                String key = entry.getKey();
                return key.startsWith(sourceIP + "_") && entry.getValue().isEmpty();
            });

            lastCleanupTime.put(sourceIP, now);
        }
    }

    private void sendAlert(String alert) {
        if (alertCallback != null) {
            alertCallback.accept(alert);
        }
    }
} 