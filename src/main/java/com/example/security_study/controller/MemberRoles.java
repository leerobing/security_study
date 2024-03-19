package com.example.security_study.controller;

public enum MemberRoles {
        USER("USER"),
        ADMIN("ADMIN");
        // Add more roles as needed

        private final String role;

        MemberRoles(String role) {
            this.role = role;
        }

        public String getRole() {
            return role;

        }
}
