package io.github.hanjungho.prguard.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

/**
 * 저장소 루트의 .prguard.yml (또는 .prguard.yaml) 파일로부터 파싱된 사용자 커스텀 보안 정책 설정
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class PrguardConfig {

    @JsonProperty("ignore_severities")
    private List<String> ignoreSeverities = new ArrayList<>();

    @JsonProperty("ignore_packages")
    private List<String> ignorePackages = new ArrayList<>();

    @JsonProperty("ignore_cves")
    private List<String> ignoreCves = new ArrayList<>();

    @JsonProperty("block_severities")
    private List<String> blockSeverities = List.of("CRITICAL", "HIGH");

    public static PrguardConfig defaultConfig() {
        return new PrguardConfig(new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), List.of("CRITICAL", "HIGH"));
    }

    /**
     * 특정 취약점이 사용자가 설정한 예외 규칙에 해당하는지 판별합니다.
     */
    public boolean isVulnerabilityIgnored(String vulnId, String pkgName, String severity) {
        if (severity != null && ignoreSeverities != null) {
            for (String ignored : ignoreSeverities) {
                if (ignored.equalsIgnoreCase(severity)) {
                    return true;
                }
            }
        }
        if (pkgName != null && ignorePackages != null) {
            for (String ignoredPkg : ignorePackages) {
                if (ignoredPkg.equalsIgnoreCase(pkgName)) {
                    return true;
                }
            }
        }
        if (vulnId != null && ignoreCves != null) {
            for (String ignoredCve : ignoreCves) {
                if (ignoredCve.equalsIgnoreCase(vulnId)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 특정 심각도가 PR 차단(BLOCK / Checks Failure) 기준에 해당하는지 판별합니다.
     */
    public boolean shouldBlock(String severity) {
        if (severity == null || blockSeverities == null) {
            return false;
        }
        for (String b : blockSeverities) {
            if (b.equalsIgnoreCase(severity)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 프롬프트 또는 로그에 출력할 커스텀 설정 요약 텍스트
     */
    public String toSummaryString() {
        if ((ignoreSeverities == null || ignoreSeverities.isEmpty()) &&
                (ignorePackages == null || ignorePackages.isEmpty()) &&
                (ignoreCves == null || ignoreCves.isEmpty())) {
            return "(기본 엔터프라이즈 정책 적용 중 - 예외 룰 없음)";
        }
        StringBuilder sb = new StringBuilder();
        if (ignoreSeverities != null && !ignoreSeverities.isEmpty()) {
            sb.append("- 무시할 심각도: ").append(ignoreSeverities).append("\n");
        }
        if (ignorePackages != null && !ignorePackages.isEmpty()) {
            sb.append("- 무시할 패키지: ").append(ignorePackages).append("\n");
        }
        if (ignoreCves != null && !ignoreCves.isEmpty()) {
            sb.append("- 무시할 CVE/보안권고: ").append(ignoreCves).append("\n");
        }
        if (blockSeverities != null && !blockSeverities.isEmpty()) {
            sb.append("- 차단(BLOCK) 기준 심각도: ").append(blockSeverities).append("\n");
        }
        return sb.toString().trim();
    }
}

