package com.growmming.gurdening.domain.dto;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class UserInfoDTO {
    private String id;
    private String email;
    @SerializedName("verified_email")
    private Boolean verifiedEmail;
    private String name;
    @SerializedName("picture")
    private String pictureUrl;
}
