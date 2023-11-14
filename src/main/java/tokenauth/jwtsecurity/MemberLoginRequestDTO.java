package tokenauth.jwtsecurity;

import lombok.Data;

@Data
public class MemberLoginRequestDTO {
    private String memberId;
    private String password;
}
