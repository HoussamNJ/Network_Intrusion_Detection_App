package ma.enset.nids.model;

import javafx.beans.property.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class NetworkPacket {
    private final ObjectProperty<LocalDateTime> timestamp;
    private final StringProperty sourceIP;
    private final StringProperty destinationIP;
    private final StringProperty protocol;
    private final IntegerProperty sourcePort;
    private final IntegerProperty destinationPort;
    private final LongProperty size;
    private final BooleanProperty intrusion;
    private final StringProperty intrusionType;
    private final String rawData;
    
    public NetworkPacket(Packet packet, boolean incoming) {
        this.timestamp = new SimpleObjectProperty<>(LocalDateTime.now());
        this.sourceIP = new SimpleStringProperty();
        this.destinationIP = new SimpleStringProperty();
        this.protocol = new SimpleStringProperty();
        this.sourcePort = new SimpleIntegerProperty();
        this.destinationPort = new SimpleIntegerProperty();
        this.size = new SimpleLongProperty(packet.length());
        this.intrusion = new SimpleBooleanProperty(false);
        this.intrusionType = new SimpleStringProperty("");
        this.rawData = packet.toString();
        
        parsePacket(packet);
    }
    
    private void parsePacket(Packet packet) {
        // Analyse du paquet IP
        IpPacket ipPacket = packet.get(IpPacket.class);
        if (ipPacket != null) {
            sourceIP.set(ipPacket.getHeader().getSrcAddr().getHostAddress());
            destinationIP.set(ipPacket.getHeader().getDstAddr().getHostAddress());
            
            // Détermination du protocole
            IpNumber protocol = ipPacket.getHeader().getProtocol();
            if (protocol != null) {
                this.protocol.set(protocol.name());
            }
            
            // Analyse des ports TCP/UDP
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                sourcePort.set(tcpPacket.getHeader().getSrcPort().valueAsInt());
                destinationPort.set(tcpPacket.getHeader().getDstPort().valueAsInt());
                
                // Détection du protocole applicatif
                TcpPort dstPort = tcpPacket.getHeader().getDstPort();
                if (dstPort.equals(TcpPort.HTTP) || dstPort.equals(TcpPort.HTTPS)) {
                    this.protocol.set(dstPort.name());
                }
            } else {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                if (udpPacket != null) {
                    sourcePort.set(udpPacket.getHeader().getSrcPort().valueAsInt());
                    destinationPort.set(udpPacket.getHeader().getDstPort().valueAsInt());
                    
                    // Détection DNS
                    if (udpPacket.getHeader().getDstPort().valueAsInt() == 53) {
                        this.protocol.set("DNS");
                    }
                }
            }
        }
    }
    
    // Getters pour les propriétés JavaFX
    public ObjectProperty<LocalDateTime> timestampProperty() {
        return timestamp;
    }
    
    public StringProperty sourceIPProperty() {
        return sourceIP;
    }
    
    public StringProperty destinationIPProperty() {
        return destinationIP;
    }
    
    public StringProperty protocolProperty() {
        return protocol;
    }
    
    public IntegerProperty sourcePortProperty() {
        return sourcePort;
    }
    
    public IntegerProperty destinationPortProperty() {
        return destinationPort;
    }
    
    public LongProperty sizeProperty() {
        return size;
    }
    
    public BooleanProperty intrusionProperty() {
        return intrusion;
    }
    
    public StringProperty intrusionTypeProperty() {
        return intrusionType;
    }
    
    // Getters et setters standards
    public LocalDateTime getTimestamp() {
        return timestamp.get();
    }
    
    public String getSourceIP() {
        return sourceIP.get();
    }
    
    public String getDestinationIP() {
        return destinationIP.get();
    }
    
    public String getProtocol() {
        return protocol.get();
    }
    
    public int getSourcePort() {
        return sourcePort.get();
    }
    
    public int getDestinationPort() {
        return destinationPort.get();
    }
    
    public long getSize() {
        return size.get();
    }
    
    public boolean isIntrusion() {
        return intrusion.get();
    }
    
    public void setIntrusion(boolean value) {
        intrusion.set(value);
    }
    
    public String getIntrusionType() {
        return intrusionType.get();
    }
    
    public void setIntrusionType(String value) {
        intrusionType.set(value);
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Timestamp: ").append(getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"))).append("\n");
        sb.append("Source IP: ").append(getSourceIP()).append("\n");
        sb.append("Destination IP: ").append(getDestinationIP()).append("\n");
        sb.append("Protocol: ").append(getProtocol()).append("\n");
        sb.append("Source Port: ").append(getSourcePort()).append("\n");
        sb.append("Destination Port: ").append(getDestinationPort()).append("\n");
        sb.append("Size: ").append(String.format("%.2f Ko", getSize() / 1024.0)).append("\n");
        if (isIntrusion()) {
            sb.append("Intrusion Type: ").append(getIntrusionType()).append("\n");
        }
        sb.append("\nRaw Data:\n").append(rawData);
        return sb.toString();
    }
} 