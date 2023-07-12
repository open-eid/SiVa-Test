package ee.openeid.siva.validation;

import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ReportType {

    public static final String SIMPLE = "Simple";
    public static final String DETAILED = "Detailed";
    public static final String DIAGNOSTIC = "Diagnostic";
}
