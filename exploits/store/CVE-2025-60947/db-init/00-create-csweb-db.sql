-- phpMyAdmin SQL Dump
-- version 4.9.2
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3308
-- Generation Time: Dec 29, 2023 at 10:13 PM
-- Server version: 5.7.28
-- PHP Version: 8.0.6

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `cspro`
--
CREATE DATABASE IF NOT EXISTS `cspro` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cspro`;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_apps`
--

DROP TABLE IF EXISTS `cspro_apps`;
CREATE TABLE IF NOT EXISTS `cspro_apps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `build_time` datetime NOT NULL,
  `path` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `version` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL,
  `files` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `signature` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `cspro_apps`
--
DROP TRIGGER IF EXISTS `tr_cspro_apps`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_apps` BEFORE INSERT ON `cspro_apps` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_binary_sync_history`
--

DROP TABLE IF EXISTS `cspro_binary_sync_history`;
CREATE TABLE IF NOT EXISTS `cspro_binary_sync_history` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `binary_data_signature` char(32) CHARACTER SET ascii NOT NULL,
  `sync_history_id` int(11) UNSIGNED NOT NULL,
  `created_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id` (`id`),
  KEY `sync_history_id` (`sync_history_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_binary_sync_history_archive`
--

DROP TABLE IF EXISTS `cspro_binary_sync_history_archive`;
CREATE TABLE IF NOT EXISTS `cspro_binary_sync_history_archive` (
  `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `binary_data_signature` char(32) CHARACTER SET ascii NOT NULL,
  `sync_history_id` int(11) UNSIGNED NOT NULL,
  `created_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id` (`id`),
  KEY `sync_history_id` (`sync_history_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_config`
--

DROP TABLE IF EXISTS `cspro_config`;
CREATE TABLE IF NOT EXISTS `cspro_config` (
  `name` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `value` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `cspro_config`
--

INSERT INTO `cspro_config` (`name`, `value`, `modified_time`, `created_time`) VALUES
('schema_version', '7', '2023-12-29 22:09:03', '2023-12-29 22:09:03'),
('server_device_id', 'c80e378c-e9f6-472e-a20d-776e44c7e060', '2023-12-29 22:09:03', '2023-12-29 22:09:03');

--
-- Triggers `cspro_config`
--
DROP TRIGGER IF EXISTS `tr_cspro_config`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_config` BEFORE INSERT ON `cspro_config` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_dictionaries`
--

DROP TABLE IF EXISTS `cspro_dictionaries`;
CREATE TABLE IF NOT EXISTS `cspro_dictionaries` (
  `id` smallint(5) UNSIGNED NOT NULL AUTO_INCREMENT,
  `dictionary_name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `dictionary_label` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `dictionary_full_content` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `dictionary_name` (`dictionary_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `cspro_dictionaries`
--
DROP TRIGGER IF EXISTS `tr_cspro_dictionaries`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_dictionaries` BEFORE INSERT ON `cspro_dictionaries` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_dictionaries_schema`
--

DROP TABLE IF EXISTS `cspro_dictionaries_schema`;
CREATE TABLE IF NOT EXISTS `cspro_dictionaries_schema` (
  `dictionary_id` smallint(5) UNSIGNED NOT NULL,
  `host_name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `schema_name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `schema_user_name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `schema_password` varbinary(255) NOT NULL,
  `additional_config` text COLLATE utf8mb4_unicode_ci,
  `map_info` text COLLATE utf8mb4_unicode_ci,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  PRIMARY KEY (`dictionary_id`),
  UNIQUE KEY `schema_name` (`schema_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `cspro_dictionaries_schema`
--
DROP TRIGGER IF EXISTS `tr_dictionaries_schema`;
DELIMITER $$
CREATE TRIGGER `tr_dictionaries_schema` BEFORE INSERT ON `cspro_dictionaries_schema` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_permissions`
--

DROP TABLE IF EXISTS `cspro_permissions`;
CREATE TABLE IF NOT EXISTS `cspro_permissions` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Permissions Table';

--
-- Dumping data for table `cspro_permissions`
--

INSERT INTO `cspro_permissions` (`id`, `name`, `modified_time`, `created_time`) VALUES
(1, 'data_all', '2023-12-29 22:09:01', '2023-12-29 22:09:01'),
(2, 'apps_all', '2023-12-29 22:09:01', '2023-12-29 22:09:01'),
(3, 'users_all', '2023-12-29 22:09:01', '2023-12-29 22:09:01'),
(4, 'roles_all', '2023-12-29 22:09:01', '2023-12-29 22:09:01'),
(5, 'reports_all', '2023-12-29 22:09:01', '2023-12-29 22:09:01'),
(6, 'dictionary_sync_upload', '2023-12-29 22:09:01', '2023-12-29 22:09:01'),
(7, 'dictionary_sync_download', '2023-12-29 22:09:01', '2023-12-29 22:09:01'),
(8, 'settings_all', '2023-12-29 22:09:01', '2023-12-29 22:09:01');

--
-- Triggers `cspro_permissions`
--
DROP TRIGGER IF EXISTS `tr_cspro_permissions`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_permissions` BEFORE INSERT ON `cspro_permissions` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_roles`
--

DROP TABLE IF EXISTS `cspro_roles`;
CREATE TABLE IF NOT EXISTS `cspro_roles` (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `rolename_unique` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Roles Table';

--
-- Dumping data for table `cspro_roles`
--

INSERT INTO `cspro_roles` (`id`, `name`, `modified_time`, `created_time`) VALUES
(1, 'Standard User', '2023-12-29 22:09:00', '2023-12-29 22:09:00'),
(2, 'Administrator', '2023-12-29 22:09:00', '2023-12-29 22:09:00');

--
-- Triggers `cspro_roles`
--
DROP TRIGGER IF EXISTS `tr_cspro_roles`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_roles` BEFORE INSERT ON `cspro_roles` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_role_dictionary_permissions`
--

DROP TABLE IF EXISTS `cspro_role_dictionary_permissions`;
CREATE TABLE IF NOT EXISTS `cspro_role_dictionary_permissions` (
  `role_id` int(10) UNSIGNED NOT NULL,
  `dictionary_id` smallint(5) UNSIGNED NOT NULL,
  `permission_id` int(10) UNSIGNED NOT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  KEY `cspro_role_dictionary_role_id_constraint` (`role_id`),
  KEY `cspro_role_dictionary_id_constraint` (`dictionary_id`),
  KEY `cspro_role_dictionary_permission_id_constraint` (`permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Role Dictionary Permissions Table';

--
-- Triggers `cspro_role_dictionary_permissions`
--
DROP TRIGGER IF EXISTS `tr_cspro_role_dictionary_permissions`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_role_dictionary_permissions` BEFORE INSERT ON `cspro_role_dictionary_permissions` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_role_permissions`
--

DROP TABLE IF EXISTS `cspro_role_permissions`;
CREATE TABLE IF NOT EXISTS `cspro_role_permissions` (
  `role_id` int(10) UNSIGNED NOT NULL,
  `permission_id` int(10) UNSIGNED NOT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  KEY `cspro_role_id_constraint` (`role_id`),
  KEY `cspro_permission_id_constraint` (`permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Role Permissions Table';

--
-- Triggers `cspro_role_permissions`
--
DROP TRIGGER IF EXISTS `tr_cspro_role_permissions`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_role_permissions` BEFORE INSERT ON `cspro_role_permissions` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_sync_history`
--

DROP TABLE IF EXISTS `cspro_sync_history`;
CREATE TABLE IF NOT EXISTS `cspro_sync_history` (
  `revision` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `device` char(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `dictionary_id` smallint(5) UNSIGNED NOT NULL,
  `universe` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `direction` enum('put','get','both') COLLATE utf8mb4_unicode_ci NOT NULL,
  `last_case_revision` int(11) UNSIGNED DEFAULT NULL,
  `last_case_guid` binary(16) DEFAULT NULL,
  `created_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`revision`),
  KEY `dictionary_id` (`dictionary_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `cspro_users`
--

DROP TABLE IF EXISTS `cspro_users`;
CREATE TABLE IF NOT EXISTS `cspro_users` (
  `username` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(2000) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `first_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `last_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `phone` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role` int(10) UNSIGNED NOT NULL,
  `modified_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_time` timestamp NULL DEFAULT '1971-01-01 05:00:00',
  PRIMARY KEY (`username`),
  KEY `role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `cspro_users`
--

INSERT INTO `cspro_users` (`username`, `password`, `first_name`, `last_name`, `email`, `phone`, `role`, `modified_time`, `created_time`) VALUES
('admin', '$2y$10$dizZqdhfRuuLTOJuEy0p4OAA4nyasTQTJenOrr4L29LVcMhCP/Eji', 'System', 'Administrator', NULL, NULL, 2, '2023-12-29 22:09:02', '2023-12-29 22:09:02');

--
-- Triggers `cspro_users`
--
DROP TRIGGER IF EXISTS `tr_cspro_users`;
DELIMITER $$
CREATE TRIGGER `tr_cspro_users` BEFORE INSERT ON `cspro_users` FOR EACH ROW SET NEW.`created_time` = CURRENT_TIMESTAMP
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `oauth_access_tokens`
--

DROP TABLE IF EXISTS `oauth_access_tokens`;
CREATE TABLE IF NOT EXISTS `oauth_access_tokens` (
  `access_token` varchar(40) COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_id` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `expires` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `scope` varchar(2000) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`access_token`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `oauth_access_tokens`
--

INSERT INTO `oauth_access_tokens` (`access_token`, `client_id`, `user_id`, `expires`, `scope`) VALUES
('a9f690ff193f16a2911c0cad19616c93f7efab13', 'cspro_android', 'admin', '2023-12-30 04:09:09', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `oauth_authorization_codes`
--

DROP TABLE IF EXISTS `oauth_authorization_codes`;
CREATE TABLE IF NOT EXISTS `oauth_authorization_codes` (
  `authorization_code` varchar(40) COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_id` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `redirect_uri` varchar(2000) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `expires` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `scope` varchar(2000) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`authorization_code`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `oauth_clients`
--

DROP TABLE IF EXISTS `oauth_clients`;
CREATE TABLE IF NOT EXISTS `oauth_clients` (
  `client_id` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_secret` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `redirect_uri` varchar(2000) COLLATE utf8mb4_unicode_ci NOT NULL,
  `grant_types` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `scope` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `user_id` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `oauth_clients`
--

INSERT INTO `oauth_clients` (`client_id`, `client_secret`, `redirect_uri`, `grant_types`, `scope`, `user_id`) VALUES
('cspro_android', 'cspro', '', NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `oauth_jwt`
--

DROP TABLE IF EXISTS `oauth_jwt`;
CREATE TABLE IF NOT EXISTS `oauth_jwt` (
  `client_id` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `subject` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `public_key` varchar(2000) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `oauth_refresh_tokens`
--

DROP TABLE IF EXISTS `oauth_refresh_tokens`;
CREATE TABLE IF NOT EXISTS `oauth_refresh_tokens` (
  `refresh_token` varchar(40) COLLATE utf8mb4_unicode_ci NOT NULL,
  `client_id` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `expires` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `scope` varchar(2000) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`refresh_token`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `oauth_refresh_tokens`
--

INSERT INTO `oauth_refresh_tokens` (`refresh_token`, `client_id`, `user_id`, `expires`, `scope`) VALUES
('088b776a642de74296bb5d49602ba09a5779b7f4', 'cspro_android', 'admin', '2024-01-13 03:09:09', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `oauth_scopes`
--

DROP TABLE IF EXISTS `oauth_scopes`;
CREATE TABLE IF NOT EXISTS `oauth_scopes` (
  `scope` text COLLATE utf8mb4_unicode_ci,
  `is_default` tinyint(1) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `oauth_users`
--

DROP TABLE IF EXISTS `oauth_users`;
CREATE TABLE IF NOT EXISTS `oauth_users` (
  `username` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password` varchar(2000) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `first_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `last_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`username`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `cspro_binary_sync_history`
--
ALTER TABLE `cspro_binary_sync_history`
  ADD CONSTRAINT `cspro_sync_history_archive_id_constraint` FOREIGN KEY (`sync_history_id`) REFERENCES `cspro_sync_history` (`revision`) ON DELETE CASCADE;

--
-- Constraints for table `cspro_binary_sync_history_archive`
--
ALTER TABLE `cspro_binary_sync_history_archive`
  ADD CONSTRAINT `cspro_sync_history_id_constraint` FOREIGN KEY (`sync_history_id`) REFERENCES `cspro_sync_history` (`revision`) ON DELETE CASCADE;

--
-- Constraints for table `cspro_dictionaries_schema`
--
ALTER TABLE `cspro_dictionaries_schema`
  ADD CONSTRAINT `schema_dict_id_constraint` FOREIGN KEY (`dictionary_id`) REFERENCES `cspro_dictionaries` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `cspro_role_dictionary_permissions`
--
ALTER TABLE `cspro_role_dictionary_permissions`
  ADD CONSTRAINT `cspro_role_dictionary_id_constraint` FOREIGN KEY (`dictionary_id`) REFERENCES `cspro_dictionaries` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `cspro_role_dictionary_permission_id_constraint` FOREIGN KEY (`permission_id`) REFERENCES `cspro_permissions` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `cspro_role_dictionary_role_id_constraint` FOREIGN KEY (`role_id`) REFERENCES `cspro_roles` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `cspro_role_permissions`
--
ALTER TABLE `cspro_role_permissions`
  ADD CONSTRAINT `cspro_permission_id_constraint` FOREIGN KEY (`permission_id`) REFERENCES `cspro_permissions` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `cspro_role_id_constraint` FOREIGN KEY (`role_id`) REFERENCES `cspro_roles` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `cspro_sync_history`
--
ALTER TABLE `cspro_sync_history`
  ADD CONSTRAINT `cspro_dict_id_constraint` FOREIGN KEY (`dictionary_id`) REFERENCES `cspro_dictionaries` (`id`);

--
-- Constraints for table `cspro_users`
--
ALTER TABLE `cspro_users`
  ADD CONSTRAINT `role_id_constraint` FOREIGN KEY (`role`) REFERENCES `cspro_roles` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
