CREATE DATABASE dbname;
USE dbname;
CREATE TABLE `user` (
                        `user_no` int(11) NOT NULL AUTO_INCREMENT,
                        `user_id` varchar(15) DEFAULT NULL,
                        `user_password` varchar(255) DEFAULT NULL,
                        `user_name` varchar(50) DEFAULT NULL,
                        `user_email` varchar(100) DEFAULT NULL,
                        `user_phone` varchar(50) DEFAULT NULL,
                        `user_birthdate` char(8) DEFAULT NULL,
                        `user_gender` char(1) DEFAULT NULL,
                        `user_terms` tinyint(1) DEFAULT NULL,
                        `user_provide_type` varchar(20) DEFAULT NULL,
                        `user_role_type` varchar(20) DEFAULT NULL,
                        `user_created_time` timestamp NULL DEFAULT NULL,
                        `user_active` tinyint(1) DEFAULT NULL,
                        PRIMARY KEY (`user_no`)
);