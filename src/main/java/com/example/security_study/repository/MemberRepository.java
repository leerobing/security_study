package com.example.security_study.repository;

import com.example.security_study.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByMemberId(String userEmail);

    Boolean existsByMemberId(String memberId);

}
