package ma.enset.nids.model;

public class DetectionRule {
    public enum RuleType {
        DOS_ATTACK,
        PORT_SCAN,
        BRUTE_FORCE,
        DDOS_ATTACK,
        TRAFFIC_ANOMALY
    }

    private final String name;
    private final RuleType type;
    private final double threshold;
    private final int timeWindowSeconds;

    public DetectionRule(String name, RuleType type, double threshold, int timeWindowSeconds) {
        this.name = name;
        this.type = type;
        this.threshold = threshold;
        this.timeWindowSeconds = timeWindowSeconds;
    }

    public String getName() {
        return name;
    }

    public RuleType getType() {
        return type;
    }

    public double getThreshold() {
        return threshold;
    }

    public int getTimeWindowSeconds() {
        return timeWindowSeconds;
    }

    @Override
    public String toString() {
        return String.format("%s [%s] - Threshold: %.2f, Window: %ds", 
            name, type, threshold, timeWindowSeconds);
    }
} 