/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19-11.7.2-MariaDB, for Linux (x86_64)
--
-- Host: 127.0.0.1    Database: mitre
-- ------------------------------------------------------
-- Server version	10.11.11-MariaDB-0ubuntu0.24.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `campaign_external_references`
--

DROP TABLE IF EXISTS `campaign_external_references`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `campaign_external_references` (
  `campaign_id` varchar(100) DEFAULT NULL,
  `source_name` varchar(100) DEFAULT NULL,
  `external_id` varchar(50) DEFAULT NULL,
  `url` text DEFAULT NULL,
  KEY `idx_campaign_extref_campaign_id` (`campaign_id`),
  KEY `idx_campaign_extref_external_id` (`external_id`),
  CONSTRAINT `campaign_external_references_ibfk_1` FOREIGN KEY (`campaign_id`) REFERENCES `campaigns` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `campaign_technique_relationships`
--

DROP TABLE IF EXISTS `campaign_technique_relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `campaign_technique_relationships` (
  `campaign_id` varchar(100) NOT NULL,
  `technique_id` varchar(100) NOT NULL,
  PRIMARY KEY (`campaign_id`,`technique_id`),
  KEY `idx_campaign_tech_campaign_id` (`campaign_id`),
  KEY `idx_campaign_tech_technique_id` (`technique_id`),
  CONSTRAINT `campaign_technique_relationships_ibfk_1` FOREIGN KEY (`campaign_id`) REFERENCES `campaigns` (`id`),
  CONSTRAINT `campaign_technique_relationships_ibfk_2` FOREIGN KEY (`technique_id`) REFERENCES `techniques` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `campaigns`
--

DROP TABLE IF EXISTS `campaigns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `campaigns` (
  `id` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `created` varchar(50) DEFAULT NULL,
  `modified` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_campaigns_id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `conversations`
--

DROP TABLE IF EXISTS `conversations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conversations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `sender` enum('user','bot') NOT NULL,
  `text` text NOT NULL,
  `image` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `conversations_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=121 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dettect_data_sources`
--

DROP TABLE IF EXISTS `dettect_data_sources`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dettect_data_sources` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `quality` int(11) DEFAULT NULL,
  `platforms` varchar(255) DEFAULT NULL,
  `collection_layers` varchar(255) DEFAULT NULL,
  `applicable_to` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `external_references`
--

DROP TABLE IF EXISTS `external_references`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `external_references` (
  `technique_id` varchar(100) DEFAULT NULL,
  `source_name` varchar(100) DEFAULT NULL,
  `external_id` varchar(50) DEFAULT NULL,
  `url` text DEFAULT NULL,
  KEY `idx_extref_technique_id` (`technique_id`),
  KEY `idx_extref_external_id` (`external_id`),
  CONSTRAINT `external_references_ibfk_1` FOREIGN KEY (`technique_id`) REFERENCES `techniques` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `group_campaign_relationships`
--

DROP TABLE IF EXISTS `group_campaign_relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `group_campaign_relationships` (
  `group_id` varchar(100) NOT NULL,
  `campaign_id` varchar(100) NOT NULL,
  PRIMARY KEY (`group_id`,`campaign_id`),
  KEY `idx_group_camp_group_id` (`group_id`),
  KEY `idx_group_camp_campaign_id` (`campaign_id`),
  CONSTRAINT `group_campaign_relationships_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`),
  CONSTRAINT `group_campaign_relationships_ibfk_2` FOREIGN KEY (`campaign_id`) REFERENCES `campaigns` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `group_external_references`
--

DROP TABLE IF EXISTS `group_external_references`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `group_external_references` (
  `group_id` varchar(100) DEFAULT NULL,
  `source_name` varchar(100) DEFAULT NULL,
  `external_id` varchar(50) DEFAULT NULL,
  `url` text DEFAULT NULL,
  KEY `idx_group_extref_group_id` (`group_id`),
  KEY `idx_group_extref_external_id` (`external_id`),
  CONSTRAINT `group_external_references_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `group_technique_relationships`
--

DROP TABLE IF EXISTS `group_technique_relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `group_technique_relationships` (
  `group_id` varchar(100) NOT NULL,
  `technique_id` varchar(100) NOT NULL,
  PRIMARY KEY (`group_id`,`technique_id`),
  KEY `idx_group_tech_group_id` (`group_id`),
  KEY `idx_group_tech_technique_id` (`technique_id`),
  CONSTRAINT `group_technique_relationships_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`),
  CONSTRAINT `group_technique_relationships_ibfk_2` FOREIGN KEY (`technique_id`) REFERENCES `techniques` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `groups`
--

DROP TABLE IF EXISTS `groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `groups` (
  `id` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `created` varchar(50) DEFAULT NULL,
  `modified` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_groups_id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `relationships`
--

DROP TABLE IF EXISTS `relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `relationships` (
  `source_id` varchar(100) NOT NULL,
  `target_id` varchar(100) NOT NULL,
  `relationship_type` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`source_id`,`target_id`),
  KEY `idx_rel_source_id` (`source_id`),
  KEY `idx_rel_target_id` (`target_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software`
--

DROP TABLE IF EXISTS `software`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `software` (
  `id` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `created` varchar(50) DEFAULT NULL,
  `modified` varchar(50) DEFAULT NULL,
  `software_type` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_software_id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_external_references`
--

DROP TABLE IF EXISTS `software_external_references`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_external_references` (
  `software_id` varchar(100) DEFAULT NULL,
  `source_name` varchar(100) DEFAULT NULL,
  `external_id` varchar(50) DEFAULT NULL,
  `url` text DEFAULT NULL,
  KEY `idx_software_extref_software_id` (`software_id`),
  KEY `idx_software_extref_external_id` (`external_id`),
  CONSTRAINT `software_external_references_ibfk_1` FOREIGN KEY (`software_id`) REFERENCES `software` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `software_technique_relationships`
--

DROP TABLE IF EXISTS `software_technique_relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `software_technique_relationships` (
  `software_id` varchar(100) NOT NULL,
  `technique_id` varchar(100) NOT NULL,
  PRIMARY KEY (`software_id`,`technique_id`),
  KEY `idx_software_tech_software_id` (`software_id`),
  KEY `idx_software_tech_technique_id` (`technique_id`),
  CONSTRAINT `software_technique_relationships_ibfk_1` FOREIGN KEY (`software_id`) REFERENCES `software` (`id`),
  CONSTRAINT `software_technique_relationships_ibfk_2` FOREIGN KEY (`technique_id`) REFERENCES `techniques` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tabletops`
--

DROP TABLE IF EXISTS `tabletops`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `tabletops` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `json_data` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `filename` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `tabletops_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `techniques`
--

DROP TABLE IF EXISTS `techniques`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `techniques` (
  `id` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `created` varchar(50) DEFAULT NULL,
  `modified` varchar(50) DEFAULT NULL,
  `attack_version` varchar(10) DEFAULT NULL,
  `tactic` text DEFAULT NULL,
  `platforms` text DEFAULT NULL,
  `detection` text DEFAULT NULL,
  `mitigation` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_techniques_id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping routines for database 'mitre'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2025-04-15 11:16:21
