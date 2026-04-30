package com.example.demo;

public interface InvoiceRepository {
    Invoice findById(Long id);
    void deleteById(Long id);
    Invoice findByIdAndByOwner(Long id);
}
