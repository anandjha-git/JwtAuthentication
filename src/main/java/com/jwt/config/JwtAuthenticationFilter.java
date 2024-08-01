package com.jwt.config;

import com.jwt.services.CustomUserDetailsService;
import com.jwt.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //get jwt
        //Bearer
        //validate
        String requestTokenHeader = request.getHeader("Authorization");
        String userName=null;
        String jwtToken=null;
        //check null and format
        if(requestTokenHeader!=null && requestTokenHeader.startsWith("Bearer ")){
            jwtToken = requestTokenHeader.substring(7); // length of "Bearer " = 6
            try{
                userName=jwtUtil.getUsernameFromToken(jwtToken);

            }catch (Exception e){
                    e.printStackTrace();
            }
            //security
            if (userName!=null && SecurityContextHolder.getContext().getAuthentication()==null){
                UserDetails userDetails =customUserDetailsService.loadUserByUsername(userName);
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());//It is used when we will implement Authority
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
            else {
                System.out.println("Username is null or Token is not validated");
            }

        }
        else {
            System.out.println("requestTokenHeader is null or Invalid format");
        }
        filterChain.doFilter(request, response);
    }
}
