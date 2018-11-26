@GenericGenerator(
        name = "usr_sequence",
        strategy = "org.hibernate.id.enhanced.SequenceStyleGenerator",
        parameters = {
                @Parameter(name = "usr_sequence", value = "sequence"),
                @Parameter(name = "initial_value", value = "1"),
                @Parameter(name = "increment_size", value = "1"),
        }
)

package testJWT.demo.domain;

import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Parameter;