package mkr.infra.web.exceptionhandler;

import lombok.extern.slf4j.Slf4j;
import mkr.infra.web.exceptionhandler.exception.ApiError;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class DefaultRestExceptionHandler extends ResponseEntityExceptionHandler {
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    @ExceptionHandler(InvalidBearerTokenException.class)
    protected ResponseEntity<Object> handleException(InvalidBearerTokenException ex) {
        return buildResponseEntity(UNAUTHORIZED, "Access denied", ex);
    }

    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<Object> handleException(HttpServletRequest request, AccessDeniedException ex) {
        var token = bearerTokenResolver.resolve(request);
        if (token == null) {
            return buildResponseEntity(UNAUTHORIZED, "Access denied", ex);
        }
        return buildResponseEntity(FORBIDDEN, "Forbidden", ex);
    }

    protected ResponseEntity<Object> buildResponseEntity(HttpStatus httpStatus, String reason, Throwable ex) {
        ApiError apiError = new ApiError(httpStatus, reason, ex);
        return new ResponseEntity<>(apiError, apiError.getStatus());
    }
}