package com.security.inmemory.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * SecurityConfig sınıfı, Spring Security yapılandırmasını içerir.
 * Uygulamanın güvenlik filtre zincirini ve kullanıcı kimlik doğrulama işlemlerini yapılandırmak için kullanılır.
 *
 * @Configuration: Sınıfın bir konfigürasyon sınıfı olduğunu belirtir.
 * @EnableWebSecurity: Web tabanlı güvenlik yapılandırmasını etkinleştirir.
 * @EnableMethodSecurity: Yöntem düzeyinde güvenlik işlemlerini etkinleştirir.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Şifrelerin güvenli bir şekilde saklanabilmesi için BCrypt algoritması kullanılır.
     *
     * @return BCryptPasswordEncoder nesnesi döner.
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Uygulamada kullanılacak kullanıcıların ve rollerin tanımlandığı bellekte tutulan kullanıcı servisini sağlar.
     * İki kullanıcı tanımlanır: biri "USER" rolüyle, diğeri "ADMIN" rolüyle.
     *
     * @return InMemoryUserDetailsManager bellekte kullanıcı bilgilerini tutar.
     */
    @Bean
    public UserDetailsService users() {
        UserDetails user1 = User.builder()
                .username("OmerKurtuldu") // Kullanıcı adı
                .password(bCryptPasswordEncoder().encode("pass1234")) // Şifre
                .roles("USER") // Kullanıcı rolü
                .build();

        UserDetails admin = User.builder()
                .username("dilara") // Admin kullanıcı adı
                .password(bCryptPasswordEncoder().encode("pass1234")) // Admin şifresi
                .roles("ADMIN") // Admin rolü
                .build();

        return new InMemoryUserDetailsManager(user1, admin);
    }

    /**
     * HttpSecurity yapılandırması ile uygulamanın güvenlik filtre zincirini yapılandırır.
     * Erişim izinleri, CSRF koruması, form girişlerini ve diğer güvenlik ayarlarını içerir.
     *
     * @param security HttpSecurity yapılandırma objesi
     * @return SecurityFilterChain, yapılandırılmış güvenlik filtre zincirini döner.
     * @throws Exception Güvenlik yapılandırmasında oluşabilecek hataları belirtir.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
        security
                // X-Frame-Options başlığını devre dışı bırakır, böylece iframe kullanımı engellenmez.
                .headers(x -> x.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                // CSRF (Cross-Site Request Forgery) korumasını devre dışı bırakır.
                .csrf(AbstractHttpConfigurer::disable)

                // Form tabanlı oturum açmayı devre dışı bırakır. Sadece HTTP Basic kullanılır.
                .formLogin(AbstractHttpConfigurer::disable)

                // /public ve /auth yollarına herkes erişebilir (kimlik doğrulaması gerekmez).
                .authorizeHttpRequests(x -> x.requestMatchers("/public/**", "/auth/**").permitAll())

                // /private/admin/** yollarına sadece "ADMIN" rolüne sahip kullanıcılar erişebilir.
                .authorizeHttpRequests(x -> x.requestMatchers("/private/admin/**").hasRole("ADMIN"))

                // /private/user/** yollarına sadece "USER" rolüne sahip kullanıcılar erişebilir.
                .authorizeHttpRequests(x -> x.requestMatchers("/private/user/**").hasRole("USER"))

                // Diğer tüm istekler kimlik doğrulaması gerektirir.
                .authorizeHttpRequests(x -> x.anyRequest().authenticated())

                // HTTP Basic Authentication ile kullanıcı doğrulaması yapılır.
                .httpBasic(Customizer.withDefaults());

        // Güvenlik yapılandırmasını tamamlar ve filtre zincirini oluşturur.
        return security.build();
    }

}
