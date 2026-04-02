-- Unified database: one table per fingerprint / indicator type.
-- MySQL 8.x, utf8mb4. Run once, then: python Fingerprint/intel_hub_ingest.py

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE DATABASE IF NOT EXISTS `threat_intel_hub`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_general_ci;

USE `threat_intel_hub`;

-- ---------------------------------------------------------------------------
-- Shared column meaning (all fp_* tables):
--   indicator_value  IOC body
--   malware_family   family / label (nullable)
--   severity         optional
--   confidence       optional
--   source           feed or pipeline name (wider than legacy intel.source)
--   last_updated     from upstream when known
--   trail_info       optional notes (e.g. Maltrail CSV column)
-- ---------------------------------------------------------------------------

-- Network / IOC strings
CREATE TABLE IF NOT EXISTS `fp_domain` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
  `indicator_value` varchar(512) NOT NULL,
  `malware_family` varchar(128) NULL,
  `severity` varchar(16) NULL,
  `confidence` int NULL,
  `source` varchar(64) NOT NULL,
  `last_updated` datetime NULL,
  `trail_info` text NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_val_src` (`indicator_value`(384), `source`(64)),
  KEY `idx_source` (`source`),
  KEY `idx_family` (`malware_family`(64))
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS `fp_ip` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_url` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_cidr` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ip_port` LIKE `fp_domain`;

-- File hashes
CREATE TABLE IF NOT EXISTS `fp_md5` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_sha1` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_sha256` LIKE `fp_domain`;

-- TLS / certs (SSLBL, JA4DB, …)
CREATE TABLE IF NOT EXISTS `fp_ssl_sha1` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ja3_md5` LIKE `fp_domain`;

-- JA4DB-style types (short strings; ja4_string can be long)
CREATE TABLE IF NOT EXISTS `fp_ja4` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ja4s` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ja4h` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ja4x` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ja4t` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ja4ts` LIKE `fp_domain`;
CREATE TABLE IF NOT EXISTS `fp_ja4tscan` LIKE `fp_domain`;

CREATE TABLE IF NOT EXISTS `fp_ja4_string` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
  `indicator_value` text NOT NULL,
  `malware_family` varchar(128) NULL,
  `severity` varchar(16) NULL,
  `confidence` int NULL,
  `source` varchar(64) NOT NULL,
  `last_updated` datetime NULL,
  `trail_info` text NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_val_src` (`indicator_value`(384), `source`(64)),
  KEY `idx_source` (`source`)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- Anything else (ThreatFox unknown ioc_type, future feeds)
CREATE TABLE IF NOT EXISTS `fp_other` (
  `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT,
  `legacy_type` varchar(32) NOT NULL COMMENT 'Original indicator_type from flat intel',
  `indicator_value` varchar(512) NOT NULL,
  `malware_family` varchar(128) NULL,
  `severity` varchar(16) NULL,
  `confidence` int NULL,
  `source` varchar(64) NOT NULL,
  `last_updated` datetime NULL,
  `trail_info` text NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_type_val_src` (`legacy_type`, `indicator_value`(256), `source`(64)),
  KEY `idx_legacy_type` (`legacy_type`)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

SET FOREIGN_KEY_CHECKS = 1;
