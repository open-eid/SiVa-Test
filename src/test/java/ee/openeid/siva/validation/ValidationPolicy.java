package ee.openeid.siva.validation;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode()
public class ValidationPolicy {

    private String name;
    private String description;
    private String url;
}
