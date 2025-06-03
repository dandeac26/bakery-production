package dev.dandeac.data_api.controller;

import dev.dandeac.data_api.dtos.IngredientDTO;
import dev.dandeac.data_api.services.IngredientService;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/ingredients")
public class IngredientController {

    private final IngredientService ingredientService;

    @Autowired
    public IngredientController(IngredientService ingredientService){
        this.ingredientService = ingredientService;
    }

    @GetMapping()
    public ResponseEntity<List<IngredientDTO>> getIngredients() {
        List<IngredientDTO> dtos = ingredientService.findIngredients();
        return new ResponseEntity<>(dtos, HttpStatus.OK);
    }

    @GetMapping("/{ingredientId}")
    public ResponseEntity<?> getIngredient(@PathVariable String ingredientId) {
        try {
            IngredientDTO dto = ingredientService.findIngredientById(ingredientId);
            return new ResponseEntity<>(dto, HttpStatus.OK);
        } catch (ResponseStatusException e) {
            return new ResponseEntity<>(e.getReason(), e.getStatusCode());
        }
    }

    @PostMapping()
    public ResponseEntity<?> addIngredient(@Valid @RequestBody IngredientDTO ingredientDTO) {
        try {
            IngredientDTO dto = ingredientService.addIngredient(ingredientDTO);
            return new ResponseEntity<>(dto, HttpStatus.CREATED);
        } catch (ResponseStatusException e) {
            return new ResponseEntity<>(e.getReason(), e.getStatusCode());
        }
    }


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getAllErrors().stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.joining(", "));
        return new ResponseEntity<>(errorMessage, HttpStatus.BAD_REQUEST);
    }

    @DeleteMapping("/{ingredientId}")
    public ResponseEntity<String> deleteIngredient(@PathVariable String ingredientId) {
        try {
            ingredientService.deleteIngredient(ingredientId);
            return new ResponseEntity<>("Ingredient with id " + ingredientId + " was deleted.", HttpStatus.NO_CONTENT);
        } catch (ResponseStatusException e) {
            return new ResponseEntity<>(e.getReason(), e.getStatusCode());
        }
    }

    @PutMapping("/{ingredientId}")
    public ResponseEntity<?> updateIngredient(@PathVariable String ingredientId,@Valid @RequestBody IngredientDTO ingredientDTO) {
        try {
            IngredientDTO dto = ingredientService.updateIngredient(ingredientId, ingredientDTO);
            return new ResponseEntity<>(dto, HttpStatus.OK);
        } catch (ResponseStatusException e) {
            return new ResponseEntity<>(e.getReason(), e.getStatusCode());
        }
    }

    @DeleteMapping()
    public ResponseEntity<String> deleteAllIngredients() {
        ingredientService.deleteAllIngredients();
        return new ResponseEntity<>("All ingredients were deleted.", HttpStatus.NO_CONTENT);
    }
}