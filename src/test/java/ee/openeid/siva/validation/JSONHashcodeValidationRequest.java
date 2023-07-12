package ee.openeid.siva.validation;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class JSONHashcodeValidationRequest {

    private List<SignatureFile> signatureFiles;
    private String signaturePolicy;
    private String reportType;
}
