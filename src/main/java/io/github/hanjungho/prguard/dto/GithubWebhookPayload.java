package io.github.hanjungho.prguard.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@NoArgsConstructor
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class GithubWebhookPayload {

    private String action;
    private Integer number;
    private Repository repository;
    private Installation installation;

    @JsonProperty("pull_request")
    private PullRequest pullRequest;

    @JsonProperty("issue")
    private Issue issue;

    @JsonProperty("comment")
    private Comment comment;

    @Getter
    @NoArgsConstructor
    @ToString
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Repository {
        @JsonProperty("full_name")
        private String fullName;

        @JsonProperty("clone_url")
        private String cloneUrl;
    }

    @Getter
    @NoArgsConstructor
    @ToString
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Installation {
        private Long id;
    }

    @Getter
    @NoArgsConstructor
    @ToString
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PullRequest {
        private Head head;

        @Getter
        @NoArgsConstructor
        @ToString
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Head {
            private String ref;
            private String sha;
            private Repository repo;
        }
    }

    @Getter
    @NoArgsConstructor
    @ToString
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Issue {
        private Integer number;

        @JsonProperty("pull_request")
        private IssuePullRequest pullRequest;

        public boolean isPullRequest() {
            return pullRequest != null;
        }
    }

    @Getter
    @NoArgsConstructor
    @ToString
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class IssuePullRequest {
        private String url;
    }

    @Getter
    @NoArgsConstructor
    @ToString
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Comment {
        private Long id;
        private String body;
        private User user;
    }

    @Getter
    @NoArgsConstructor
    @ToString
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class User {
        private String login;
        private String type;
    }
}
