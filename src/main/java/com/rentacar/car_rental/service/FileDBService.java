package com.rentacar.car_rental.service;

import com.rentacar.car_rental.domain.FileDB;
import com.rentacar.car_rental.repository.FileDBRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Objects;
import java.util.stream.Stream;

@Service
@AllArgsConstructor
public class FileDBService {

    private final FileDBRepository fileDBRepository;

    public FileDB store(MultipartFile file) throws IOException {
        String fileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));

        FileDB fileDB = new FileDB(fileName, file.getContentType(), file.getBytes());
        fileDBRepository.save(fileDB);

        return fileDB;
    }

    public FileDB getFile(String id){
        return fileDBRepository.findById(id).get();
    }

    public Stream<FileDB> getAllFiles(){
        return fileDBRepository.findAll().stream();
    }

}
