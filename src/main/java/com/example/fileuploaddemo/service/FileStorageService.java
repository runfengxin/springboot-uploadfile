package com.example.fileuploaddemo.service;

import com.example.fileuploaddemo.common.ErrorEnum;
import com.example.fileuploaddemo.common.ResourceBusiness;
import com.example.fileuploaddemo.common.ResourceType;
import com.example.fileuploaddemo.exception.CodeException;
import com.example.fileuploaddemo.util.DateUtil;
import com.example.fileuploaddemo.util.EncryptUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

@Service
@Slf4j
public class FileStorageService {

    @Value("${tl.conf.ossPath}")
    private String ossPath;

    /**
     * 保存图片并生成相对路径
     * @param file
     * @param type
     * @param business
     * @return
     */
    public String storeFile(MultipartFile file, ResourceType type, ResourceBusiness business) {
        if (file == null) {
            throw new CodeException(ErrorEnum.FILE_IS_NULL);
        }
        Path locationPath = getResPath(type, business);
        String fileName = randomFileName(StringUtils.cleanPath(file.getOriginalFilename()));
        try {
            if (Files.notExists(locationPath)){
                Files.createDirectories(locationPath);
            }

            Path targetLocation = locationPath.resolve(fileName);
            log.info("保存路径：" + targetLocation.toString());
            Files.copy(file.getInputStream(), targetLocation, StandardCopyOption.REPLACE_EXISTING);
            return "/" + type + "/" + business + "/" + fileName;
        } catch (IOException e) {
            //throw new FileStorageException("Could not store file " + fileName + ". Please try again!", ex);
            log.info("Could not store file " + fileName + ". Please try again!");
            throw new CodeException(0012, "Could not store file " + fileName + ". Please try again!");
        }
    }

    /**
     * 加载文件为资源文件
     * @param fileName
     * @return
     */
    public Resource loadFileAsResource(String fileName, ResourceType type, ResourceBusiness business) {
        try{
            Path fileStorageLocation = getResPath(type, business);
            Path filePath = fileStorageLocation.resolve(fileName).normalize();
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists()) {
                return resource;
            } else {
                throw new CodeException(0013, "找不到"+fileName);
            }

        } catch (MalformedURLException e) {
            throw new CodeException(0013, "找不到"+fileName);
        }
    }

    /**
     * 获取资源相应的目录
     * @return
     */
    public Path getResPath(ResourceType type, ResourceBusiness business) {
        StringBuilder pathBuilder= new StringBuilder(ossPath);
        // 资源按类型区分目录
        switch (type) {
            case IMAGE:
                pathBuilder.append("/image");
                break;
            case VIDEO:
                pathBuilder.append("/video");
                break;
            case VOICE:
                pathBuilder.append("/voice");
                break;
            default:
                pathBuilder.append("/other");
                break;
        }

        // 资源按业务区分目录
        switch (business) {
            case AVATAR:
            case USER:
            case PHOTO:
            case ALBUM:
            case ESSAY:
                pathBuilder.append("/user");
//			if (usr != null) {
//				pathBuilder.append("_").append(usr.getUsrid());
//			}
                break;

            case ATTACH:
                pathBuilder.append("/att");
                break;

            case SYS:
                pathBuilder.append("/system");
                break;

            case FEEDBACK:
                pathBuilder.append("/manager");
                break;

            default:
                pathBuilder.append("/other");
                break;
        }
        return Paths.get(pathBuilder.toString()).toAbsolutePath().normalize();
    }

    /**
     * 文件名为：随机数_时间.后缀
     * @return
     */
    private String randomFileName(String fileName) {
        StringBuilder nameBuilder = new StringBuilder();
        //生成随机数
        nameBuilder.append(EncryptUtil.genId());
        nameBuilder.append("_"+ DateUtil.getTodayStr());
        int index = fileName.lastIndexOf(".");
        nameBuilder.append(fileName.substring(index, fileName.length()));
        return nameBuilder.toString();
    }

}
