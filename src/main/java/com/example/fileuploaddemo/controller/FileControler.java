package com.example.fileuploaddemo.controller;

import com.example.fileuploaddemo.common.ResourceBusiness;
import com.example.fileuploaddemo.common.ResourceType;
import com.example.fileuploaddemo.service.FileStorageService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RestController
@Slf4j
public class FileControler {

    @Autowired
    private FileStorageService fileStorageService;

    @RequestMapping(value = "/uploadFile", method = RequestMethod.POST)
    public String uploadFile(MultipartFile file, ResourceType type, ResourceBusiness business) {
//        if (StringUtils.isEmpty(file) || StringUtils.isEmpty(type) || StringUtils.isEmpty(business)) {
//            throw new CodeException(ResultCode.PARAM_ERR);
//        }
        return fileStorageService.storeFile(file, ResourceType.IMAGE, ResourceBusiness.AVATAR);
//        String fileDownloadUri = ServletUriComponentsBuilder.fromCurrentContextPath()
//                .path("/" + type.name())
//                .path("/" + business.name())
//                .path("/" + fileName)
//                .toUriString();

    }

    @GetMapping("/oss/{type}/{business}/{fileName:.+}")
//    @ApiImplicitParams({@ApiImplicitParam(name = "fileName", paramType = "path", value = "文件名称", required = true)})
    public ResponseEntity<Resource> downloadFile(@PathVariable String fileName, @PathVariable ResourceType type, @PathVariable ResourceBusiness business, HttpServletRequest request) {
        Resource resource = fileStorageService.loadFileAsResource(fileName, type, business);
        String contentType = null;
        try {
            contentType = request.getServletContext().getMimeType(resource.getFile().getAbsolutePath());
        } catch (IOException e) {
            log.info("counld not determine file type.");
        }
        if (contentType == null) {
            contentType = "application/octet-stream";
        }
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION)
                .body(resource);
    }
}
