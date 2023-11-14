package tokenauth.jwtsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/members")
@RequiredArgsConstructor
public class TokenController {

    private final MemberService memberService;

    @PostMapping("/login")
    public TokenDTO login(@RequestBody MemberLoginRequestDTO memberLoginRequestDTO) {
        String memberId = memberLoginRequestDTO.getMemberId();
        String password = memberLoginRequestDTO.getPassword();
        TokenDTO tokenDTO = memberService.login(memberId, password);
        return tokenDTO;
    }

    @PostMapping("/test")
    public String test() {
        return "success";
    }
}
