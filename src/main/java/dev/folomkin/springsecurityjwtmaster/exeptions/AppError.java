package dev.folomkin.springsecurityjwtmaster.exeptions;


import lombok.Data;

import java.util.Date;

@Data
public class AppError {
    private int Status;
    private String message;
    private Date timeStamp;

    public AppError(int status, String message) {
        Status = status;
        this.message = message;
        this.timeStamp = new Date();
    }
}
