package employees;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Controller
@AllArgsConstructor
@Slf4j
public class EmployeesController {

    private EmployeesClient employeesClient;

    @GetMapping("/")
    public ModelAndView listEmployees(Principal principal) {
        log.debug("Principal: {}", principal);
        Map<String, Object> model = new HashMap<>();
        model.put("employees", employeesClient.listEmployees());

        // SecurityContextHolder.getContext().getAuthentication().getPrincipal()

        return new ModelAndView("index", model);
    }

    @GetMapping("/create-employee")
    public ModelAndView createEmployee() {
        var model = Map.of(
                "command", new Employee(null, "")
        );
        return new ModelAndView("create-employee", model);
    }

    @PostMapping("/create-employee")
    public ModelAndView createEmployeePost(@ModelAttribute Employee command) {
        employeesClient.createEmployee(command);
        return new ModelAndView("redirect:/");
    }

}