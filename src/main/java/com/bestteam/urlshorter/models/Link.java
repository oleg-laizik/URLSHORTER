package com.bestteam.urlshorter.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "link")
public class Link {
    @Id
    @Column(name = "short_link")
    String shortLink;

    String link;

    @Column(name = "open_count")
    int openCount;

    int user_id;
}
