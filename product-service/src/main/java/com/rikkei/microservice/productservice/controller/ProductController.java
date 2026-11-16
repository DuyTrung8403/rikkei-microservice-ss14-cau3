package com.rikkei.microservice.productservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private static final Map<Integer, Map<String, Object>> PRODUCTS_DB = new ConcurrentHashMap<>();

    static {
        PRODUCTS_DB.put(1, Map.of("id", 1, "name", "MacBook Pro M3", "price", 2000));
        PRODUCTS_DB.put(2, Map.of("id", 2, "name", "Dell XPS 15", "price", 1600));
        PRODUCTS_DB.put(3, Map.of("id", 3, "name", "iPad Pro 12.9", "price", 1100));
    }

    // GET /api/products: Cho phép mọi user đã đăng nhập truy cập
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> getAllProducts() {
        return ResponseEntity.ok(new ArrayList<>(PRODUCTS_DB.values()));
    }

    // DELETE /api/products/{id}: Chỉ cho phép User có Role ADMIN thực hiện
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> deleteProduct(@PathVariable("id") Integer id) {
        if (!PRODUCTS_DB.containsKey(id)) {
            return ResponseEntity.notFound().build();
        }
        PRODUCTS_DB.remove(id);
        return ResponseEntity.ok(Map.of(
                "message", "Product with id " + id + " has been successfully deleted by ADMIN",
                "productId", id
        ));
    }
}
