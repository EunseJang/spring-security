package spring.security.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

    // Swagger 설정을 위한 Docket 빈 생성
    @Bean
    public Docket fitnessRecordService() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                // API 문서를 생성할 대상 패키지 지정
                .apis(RequestHandlerSelectors.basePackage("spring.security"))
                .paths(PathSelectors.any())
                .build().apiInfo(apiInfo());
    }

    // API 문서 정보 설정
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Spring Security Study")
                .description("스프링 시큐리티 공부용 스웨거")
                .version("1.0.0")
                .build();
    }
}
