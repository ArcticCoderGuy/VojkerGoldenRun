import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {

  // Demo “versions” (näkyy auditissa)
  static final String PACK_NAME = "trade.demo";
  static final String PACK_VERSION = "1.0.0";
  static final String ENGINE_NAME = "java-ref-no-deps";
  static final String ENGINE_VERSION = "1.0.0";

  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      System.out.println("USAGE:");
      System.out.println("  java -cp out Main <case_dir>");
      System.out.println("  java -cp out Main --bless <case_dir>");
      System.exit(2);
    }

    boolean bless = false;
    int idx = 0;
    if (args[0].equals("--bless")) {
      bless = true;
      idx = 1;
    }
    if (idx >= args.length) {
      System.out.println("ERROR: missing <case_dir>");
      System.exit(2);
    }

    Path caseDir = Paths.get(args[idx]);
    String caseName = caseDir.getFileName().toString();

    Path inputPath = caseDir.resolve("golden_input.json");
    Path expectedPath = caseDir.resolve("expected_audit.json");
    Path actualPath = caseDir.resolve("actual_audit.json");

    byte[] inputBytes = Files.readAllBytes(inputPath);
    // Tässä demossa “canonical input” = file bytes. Sama bytes -> sama hash.
    String snapshotHash = sha256Hex(inputBytes);

    String input = new String(inputBytes, StandardCharsets.UTF_8);

    // --- Pipeline: Input -> Snapshot -> Guards -> FSM -> Decision -> Audit(JSON bytes)
    Snapshot s = Snapshot.fromCanonicalJson(input);

    List<GuardTrace> trace = new ArrayList<>();
    Decision decision = runGuardsAndDecide(s, trace);

    String[] statePath = decision.decision.equals("GO")
        ? new String[]{"IDLE","ARMED","ACTION"}
        : new String[]{"IDLE"};

    String auditJson = buildAuditJson(
        caseName,
        snapshotHash,
        s.timestamp,
        trace,
        statePath,
        decision
    );

    byte[] actualBytes = auditJson.getBytes(StandardCharsets.UTF_8);
    Files.write(actualPath, actualBytes);

    // Bless = kirjoita expected = actual (kehityksessä). Showtimessa älä blessaa.
    if (bless || !Files.exists(expectedPath)) {
      Files.write(expectedPath, actualBytes);
      System.out.println("BLESSED expected_audit.json for case=" + caseName);
      System.out.println("WROTE " + expectedPath.toString());
      System.out.println("WROTE " + actualPath.toString());
      System.exit(0);
    }

    byte[] expectedBytes = Files.readAllBytes(expectedPath);
    boolean ok = Arrays.equals(expectedBytes, actualBytes);

    System.out.println("CASE=" + caseName);
    System.out.println("SNAPSHOT_HASH=" + snapshotHash);
    System.out.println("EXPECTED_SHA256=" + sha256Hex(expectedBytes));
    System.out.println("ACTUAL_SHA256=" + sha256Hex(actualBytes));

    if (ok) {
      System.out.println("GOLDEN_MATCH=PASS");
      System.exit(0);
    } else {
      int at = firstMismatchIndex(expectedBytes, actualBytes);
      System.out.println("GOLDEN_MATCH=FAIL");
      System.out.println("FIRST_MISMATCH_AT_BYTE=" + at);
      System.exit(1);
    }
  }

  // ---------------------------
  // Guards + Decision (fail-fast, order-locked)
  // ---------------------------
  static Decision runGuardsAndDecide(Snapshot s, List<GuardTrace> trace) {
    // 1) ValidationGuard
    {
      String reason = null;
      if (isBlank(s.symbol)) reason = "VALIDATION_MISSING_SYMBOL";
      else if (isBlank(s.timeframe)) reason = "VALIDATION_MISSING_TIMEFRAME";
      else if (Double.isNaN(s.open) || Double.isNaN(s.close)) reason = "VALIDATION_MISSING_OHLC";
      GuardTrace t = new GuardTrace("ValidationGuard", reason == null, reason);
      trace.add(t);
      if (!t.pass) return Decision.noGo(reason);
    }

    // 2) PolicyGuard
    {
      String reason = null;
      if (!"M1".equals(s.timeframe)) reason = "POLICY_TIMEFRAME_BLOCKED";
      GuardTrace t = new GuardTrace("PolicyGuard", reason == null, reason);
      trace.add(t);
      if (!t.pass) return Decision.noGo(reason);
    }

    // 3) RiskGuard
    {
      String reason = null;
      if (s.volume <= 0) reason = "RISK_VOLUME_ZERO";
      GuardTrace t = new GuardTrace("RiskGuard", reason == null, reason);
      trace.add(t);
      if (!t.pass) return Decision.noGo(reason);
    }

    // 4) CooldownGuard (demo: always pass)
    {
      GuardTrace t = new GuardTrace("CooldownGuard", true, null);
      trace.add(t);
    }

    // 5) SignalGuard
    {
      String reason = null;
      if (s.close == s.open) reason = "SIGNAL_FLAT_BAR";
      GuardTrace t = new GuardTrace("SignalGuard", reason == null, reason);
      trace.add(t);
      if (!t.pass) return Decision.noGo(reason);
    }

    // Decision (deterministinen)
    if (s.close < s.open) {
      return Decision.go("OPEN_TRADE", "SHORT", new String[]{"CLOSE_BELOW_OPEN"});
    } else {
      return Decision.go("OPEN_TRADE", "LONG", new String[]{"CLOSE_ABOVE_OR_EQUAL_OPEN"});
    }
  }

  // ---------------------------
  // Data contracts
  // ---------------------------
  static final class Snapshot {
    final String symbol;
    final String timeframe;
    final long timestamp;
    final double open;
    final double close;
    final double volume;

    Snapshot(String symbol, String timeframe, long timestamp, double open, double close, double volume) {
      this.symbol = symbol;
      this.timeframe = timeframe;
      this.timestamp = timestamp;
      this.open = open;
      this.close = close;
      this.volume = volume;
    }

    static Snapshot fromCanonicalJson(String json) {
      // “No deps” demo: poimitaan vain tarvittavat kentät yksinkertaisella key-haulla.
      String symbol = extractString(json, "symbol");
      String timeframe = extractString(json, "timeframe");
      long timestamp = (long) extractNumber(json, "timestamp");
      double open = extractNumber(json, "open");
      double close = extractNumber(json, "close");
      double volume = extractNumber(json, "volume");
      return new Snapshot(symbol, timeframe, timestamp, open, close, volume);
    }
  }

  static final class GuardTrace {
    final String guard;
    final boolean pass;
    final String reason; // null if pass

    GuardTrace(String guard, boolean pass, String reason) {
      this.guard = guard;
      this.pass = pass;
      this.reason = reason;
    }
  }

  static final class Decision {
    final String decision; // GO / NO_GO
    final String action;   // OPEN_TRADE / DO_NOTHING
    final String direction; // SHORT / LONG / NONE
    final String[] reasonCodes;

    Decision(String decision, String action, String direction, String[] reasonCodes) {
      this.decision = decision;
      this.action = action;
      this.direction = direction;
      this.reasonCodes = reasonCodes;
    }

    static Decision noGo(String reason) {
      return new Decision("NO_GO", "DO_NOTHING", "NONE", new String[]{reason});
    }

    static Decision go(String action, String direction, String[] reasons) {
      return new Decision("GO", action, direction, reasons);
    }
  }

  // ---------------------------
  // Deterministic audit JSON (single-line, stable key order)
  // ---------------------------
  static String buildAuditJson(
      String caseName,
      String snapshotHash,
      long timestamp,
      List<GuardTrace> trace,
      String[] statePath,
      Decision d
  ) {
    String tsUtc = Instant.ofEpochSecond(timestamp).toString();

    StringBuilder sb = new StringBuilder(512);
    sb.append("{");
    sb.append(q("schema")).append(":").append(q("vojker.audit.v1")).append(",");
    sb.append(q("snapshot_hash")).append(":").append(q(snapshotHash)).append(",");
    sb.append(q("pack")).append(":{")
        .append(q("name")).append(":").append(q(PACK_NAME)).append(",")
        .append(q("version")).append(":").append(q(PACK_VERSION))
        .append("},");
    sb.append(q("engine")).append(":{")
        .append(q("name")).append(":").append(q(ENGINE_NAME)).append(",")
        .append(q("version")).append(":").append(q(ENGINE_VERSION))
        .append("},");
    sb.append(q("decision")).append(":{")
        .append(q("decision")).append(":").append(q(d.decision)).append(",")
        .append(q("action")).append(":").append(q(d.action)).append(",")
        .append(q("direction")).append(":").append(q(d.direction))
        .append("},");
    sb.append(q("state_path")).append(":").append(jsonArray(statePath)).append(",");
    sb.append(q("reason_codes")).append(":").append(jsonArray(d.reasonCodes)).append(",");
    sb.append(q("guard_trace")).append(":[");
    for (int i = 0; i < trace.size(); i++) {
      GuardTrace t = trace.get(i);
      if (i > 0) sb.append(",");
      sb.append("{")
        .append(q("guard")).append(":").append(q(t.guard)).append(",")
        .append(q("pass")).append(":").append(t.pass ? "true" : "false");
      if (!t.pass) {
        sb.append(",").append(q("reason")).append(":").append(q(t.reason));
      }
      sb.append("}");
    }
    sb.append("],");
    sb.append(q("meta")).append(":{")
        .append(q("run_id")).append(":").append(q("golden-v1-" + caseName)).append(",")
        .append(q("timestamp_utc")).append(":").append(q(tsUtc))
        .append("}");
    sb.append("}");
    return sb.toString();
  }

  // ---------------------------
  // Helpers (no deps)
  // ---------------------------
  static String q(String s) { return "\"" + jsonEscape(s) + "\""; }

  static String jsonEscape(String s) {
    StringBuilder sb = new StringBuilder(s.length() + 8);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '\\': sb.append("\\\\"); break;
        case '"': sb.append("\\\""); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int)c));
          } else {
            sb.append(c);
          }
      }
    }
    return sb.toString();
  }

  static String jsonArray(String[] items) {
    StringBuilder sb = new StringBuilder();
    sb.append("[");
    for (int i = 0; i < items.length; i++) {
      if (i > 0) sb.append(",");
      sb.append(q(items[i]));
    }
    sb.append("]");
    return sb.toString();
  }

  static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }

  static String extractString(String json, String key) {
    String needle = "\"" + key + "\":\"";
    int i = json.indexOf(needle);
    if (i < 0) return null;
    int start = i + needle.length();
    int end = json.indexOf("\"", start);
    if (end < 0) return null;
    return json.substring(start, end);
  }

  static double extractNumber(String json, String key) {
    String needle = "\"" + key + "\":";
    int i = json.indexOf(needle);
    if (i < 0) return Double.NaN;
    int start = i + needle.length();
    int end = start;
    while (end < json.length()) {
      char c = json.charAt(end);
      if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
        end++;
      } else {
        break;
      }
    }
    try {
      return Double.parseDouble(json.substring(start, end));
    } catch (Exception e) {
      return Double.NaN;
    }
  }

  static String sha256Hex(byte[] data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(data);
    StringBuilder sb = new StringBuilder(digest.length * 2);
    for (byte b : digest) sb.append(String.format("%02x", b));
    return sb.toString();
  }

  static int firstMismatchIndex(byte[] a, byte[] b) {
    int n = Math.min(a.length, b.length);
    for (int i = 0; i < n; i++) {
      if (a[i] != b[i]) return i;
    }
    return n; // one is prefix of the other
  }
}
