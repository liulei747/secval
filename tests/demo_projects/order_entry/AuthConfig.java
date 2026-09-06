// 仅用于测试审计系统的合成代码，不是生产项目。
public class AuthConfig {

    public jakarta.servlet.Filter authFilter() {
        return (request, response, chain) -> {
            String token = request.getHeader("Authorization");
            if (token == null || token.isEmpty()) {
                throw new SecurityException("missing token");
            }
            chain.doFilter(request, response);
        };
    }
}
