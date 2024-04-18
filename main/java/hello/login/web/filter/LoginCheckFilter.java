package hello.login.web.filter;

import hello.login.web.SessionConst;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.PatternMatchUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
public class LoginCheckFilter implements Filter {

    private static final String[] whitelist ={"/", "/members/add","/login" ,"/logout", "/css/*"};
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequst = (HttpServletRequest) request;
        String requestURI = httpRequst.getRequestURI();

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            log.info("인증 체크 필터 시작{}",requestURI);

            if (isLoginCheckPath(requestURI)){
                log.info("인증 체크 로직 실행{}", requestURI);
                HttpSession session = httpRequst.getSession(false);
                if(session ==null || session.getAttribute(SessionConst.LOGIN_MEMBER ) ==null){
                    log.info("미인증 사용자 요청 {}",requestURI);
                    // 다시 리다이렉트 시키기 이전페이지로
                    httpResponse.sendRedirect("/login?redirectURL=" +requestURI);
                    return;
                }
            }
        chain.doFilter(request,response);
        }catch (Exception e){
            throw e; //예외 로깅가능, 톰캣까지 보내줘야함
        }finally {
            log.info("인증 체크 필터 종료 {}", request);
        }
    }
    //화이트리스트 체크 x

    private boolean isLoginCheckPath(String requstURI){
        return !PatternMatchUtils.simpleMatch(whitelist, requstURI);
    }
}
