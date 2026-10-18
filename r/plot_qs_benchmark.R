# Quantum-safe benchmark charts against IBM Redbook SG24-8525-01.
# Input:  reports/figures_data/qs_*.csv   (python3 scripts/qs_benchmark.py)
# Output: reports/figures/09..13_qs_*.png
# Run from the project root:  Rscript r/plot_qs_benchmark.R
suppressPackageStartupMessages(library(ggplot2))
options(bitmapType = "cairo")

data_dir <- "reports/figures_data"
out_dir  <- "reports/figures"
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)
theme_set(theme_minimal(base_size = 13) +
  theme(plot.title.position = "plot", plot.caption.position = "plot",
        plot.title = element_text(face = "bold")))
blue <- "#1F5FAD"; grey <- "#9AA5B1"; orange <- "#D9822B"; red <- "#B83A3A"
ref_note <- "Reference: IBM Redbook SG24-8525-01, Transitioning to Quantum-Safe Cryptography on IBM Z"

save_plot <- function(p, name, w = 8, h = 5) {
  ggsave(file.path(out_dir, name), p, width = w, height = h, dpi = 150, bg = "white")
  cat("saved", file.path(out_dir, name), "\n")
}
read_qs <- function(f) read.csv(file.path(data_dir, f), stringsAsFactors = FALSE)
log_breaks <- c(10, 100, 1e3, 1e4, 1e5)
log_labels <- c("10", "100", "1k", "10k", "100k")
fmt_k <- function(x) ifelse(x >= 1000, paste0(round(x / 1000, 1), "k"), as.character(round(x)))

# 9. Every crypto use, classified with Redbook Table 1-1 -----------------------
inv <- read_qs("qs_inventory.csv")
inv$where <- ifelse(tolower(as.character(inv$in_pipeline)) == "true", "Redaction pipeline", "Team workflow (out of scope)")
inv$redbook_status <- factor(inv$redbook_status,
                             levels = c("Quantum-safe", "Secure", "Broken alone, paired with ML-DSA", "Broken"))
inv$label <- paste0(inv$algorithm, "  -  ", inv$purpose, "  (", inv$component, ")")
inv$label <- factor(inv$label, levels = rev(inv$label[order(inv$where, inv$redbook_status)]))
safe <- mean(inv$redbook_status[inv$where == "Redaction pipeline"] != "Broken")
p9 <- ggplot(inv, aes(redbook_status, label, colour = redbook_status)) +
  geom_point(size = 5) +
  facet_grid(where ~ ., scales = "free_y", space = "free_y") +
  scale_colour_manual(values = c("Quantum-safe" = blue, Secure = "#6C8EBF",
                                 "Broken alone, paired with ML-DSA" = orange, Broken = red), drop = FALSE) +
  scale_x_discrete(drop = FALSE, labels = function(x) sub("Broken alone, paired with ML-DSA",
                                                         "Broken alone,\npaired with ML-DSA", x)) +
  labs(title = sprintf("%d%% of the pipeline's crypto survives a quantum computer", round(100 * safe)),
       subtitle = paste0("Each crypto use classified with Redbook Table 1-1: AES and SHA-2/3 secure, RSA and ECC broken;\n",
                         "ML-DSA quantum-safe (FIPS 204). Ed25519 is only used inside the dual signature, never alone."),
       x = "Quantum computer impact (Table 1-1)", y = NULL, caption = ref_note) +
  theme(legend.position = "none", strip.text.y = element_text(angle = 0, face = "bold", hjust = 0),
        panel.grid.major.y = element_blank())
save_plot(p9, "09_qs_inventory.png", 11, 5)

# 10. Key and signature sizes: measured vs Redbook Table 6-1 --------------------
sig <- read_qs("qs_signatures.csv")
long <- rbind(
  data.frame(algorithm = sig$algorithm, family = sig$family, part = "Public key",  measured = sig$public,    ref = sig$ref_public),
  data.frame(algorithm = sig$algorithm, family = sig$family, part = "Private key", measured = sig$private,   ref = sig$ref_private),
  data.frame(algorithm = sig$algorithm, family = sig$family, part = "Signature",   measured = sig$signature, ref = sig$ref_signature))
long$part <- factor(long$part, levels = c("Public key", "Private key", "Signature"))
long$pqc <- ifelse(grepl("PQC", long$family), "Post-quantum (ML-DSA)", "Classical (broken by Shor)")
long$algorithm <- factor(long$algorithm, levels = unique(sig$algorithm[order(grepl("PQC", sig$family), sig$signature)]))
long$label <- ifelse(is.na(long$ref), as.character(long$measured),
                     ifelse(long$measured == long$ref, paste0(long$measured, "  = Redbook"),
                            paste0(long$measured, "  (Redbook ", long$ref, ")")))
ml65 <- sig$signature[sig$algorithm == "ML-DSA-65"]
ratio <- function(a) round(ml65 / sig$signature[sig$algorithm == a])
ttl10 <- if (length(ml65) && any(sig$algorithm == "Ed25519") && any(sig$algorithm == "RSA-4096 (CRT)"))
  sprintf("An ML-DSA-65 signature is %dx RSA-4096 and %dx Ed25519", ratio("RSA-4096 (CRT)"), ratio("Ed25519")) else
  "Quantum-safe keys and signatures are much larger"
p10 <- ggplot(long, aes(algorithm, measured, fill = pqc)) +
  geom_col(width = 0.7) +
  geom_text(aes(label = label), hjust = -0.08, size = 3.1) +
  facet_wrap(~ part, nrow = 1) +
  coord_flip() +
  scale_y_log10(breaks = log_breaks, labels = log_labels, expand = expansion(mult = c(0, 0.9))) +
  scale_fill_manual(values = c("Post-quantum (ML-DSA)" = blue, "Classical (broken by Shor)" = grey)) +
  labs(title = ttl10,
       subtitle = paste0("Bytes measured on this machine (log scale), with the Redbook Table 6-1 value in brackets.\n",
                         "Redbook sizes are CCA key tokens; RSA/ECC here are DER/raw encodings. Redbook's 3293-byte ML-DSA-65\n",
                         "signature is the pre-standard Dilithium size; final FIPS 204 is 3309."),
       x = NULL, y = "bytes (log scale)", fill = NULL, caption = ref_note) +
  theme(legend.position = "top")
save_plot(p10, "10_qs_sizes.png", 13, 6)

# 11. Signing and verification speed -------------------------------------------
sp <- rbind(data.frame(algorithm = sig$algorithm, family = sig$family, op = "Sign",   per_s = sig$sign_per_s),
            data.frame(algorithm = sig$algorithm, family = sig$family, op = "Verify", per_s = sig$verify_per_s))
sp <- subset(sp, !is.na(per_s))
sp$pqc <- ifelse(grepl("PQC", sp$family), "Post-quantum (ML-DSA)", "Classical (broken by Shor)")
sp$algorithm <- factor(sp$algorithm, levels = levels(long$algorithm))
p11 <- ggplot(sp, aes(algorithm, per_s, fill = pqc)) +
  geom_col(width = 0.7) +
  geom_text(aes(label = fmt_k(per_s)), hjust = -0.15, size = 3.4) +
  facet_wrap(~ op) +
  coord_flip() +
  scale_y_log10(breaks = log_breaks, labels = log_labels, expand = expansion(mult = c(0, 0.3))) +
  scale_fill_manual(values = c("Post-quantum (ML-DSA)" = blue, "Classical (broken by Shor)" = grey)) +
  labs(title = "ML-DSA signs and verifies fast enough for every redaction",
       subtitle = "Operations per second on a single core of this machine (1 KiB message, log scale)",
       x = NULL, y = "operations per second (log scale)", fill = NULL,
       caption = "Speed is not in the Redbook; measured with liboqs (ML-DSA) and OpenSSL (classical)") +
  theme(legend.position = "top")
save_plot(p11, "11_qs_speed.png", 10, 5)

# 12. Scorecard: Redbook journey (2-1), agility (2-4), inventory (2-3) ----------
sc <- read_qs("qs_scorecard.csv")
sc$status <- ifelse(is.na(sc$score), "Not applicable", c("Not done", "Partial", "Done")[sc$score + 1])
sc$status <- factor(sc$status, levels = c("Done", "Partial", "Not done", "Not applicable"))
sc$frac <- ifelse(is.na(sc$score) | sc$max == 0, 0, sc$score / sc$max)
sc$score[is.na(sc$score)] <- 0
sc$framework <- factor(sc$framework, levels = unique(sc$framework))
sc$item <- factor(sc$item, levels = rev(unique(sc$item)))
totals <- aggregate(cbind(score, max) ~ framework, sc, sum)
totals$lab <- sprintf("%s\n%d / %d", totals$framework, totals$score, totals$max)
sc$framework_lab <- factor(totals$lab[match(sc$framework, totals$framework)], levels = totals$lab)
p12 <- ggplot(sc, aes(frac, item, fill = status)) +
  geom_col(width = 0.7) +
  geom_text(data = subset(sc, status == "Not applicable"), aes(x = 0.01, label = "not applicable: no network protocol"),
            hjust = 0, size = 3.6, colour = "grey40") +
  facet_grid(framework_lab ~ ., scales = "free_y", space = "free_y") +
  scale_x_continuous(labels = function(x) paste0(round(100 * x), "%"), limits = c(0, 1), breaks = c(0, 0.5, 1)) +
  scale_fill_manual(values = c(Done = blue, Partial = orange, "Not done" = grey, "Not applicable" = "white"),
                    breaks = c("Done", "Partial", "Not done"), drop = FALSE) +
  labs(title = "Project scored against the Redbook's quantum-safe framework",
       subtitle = "Each item: 0 = not done, 1 = partial, 2 = done. Evidence per item in reports/qs_benchmark.json",
       x = NULL, y = NULL, fill = NULL, caption = ref_note) +
  theme(legend.position = "top", strip.text.y = element_text(angle = 0, face = "bold", hjust = 0),
        panel.grid.major.y = element_blank())
save_plot(p12, "12_qs_scorecard.png", 11, 7)

# 13. Cost of security: audit log per signer + symmetric throughput -------------
au <- read_qs("qs_audit.csv")
au_long <- rbind(data.frame(signer = au$signer, metric = "Signed entries per second", value = au$entries_per_s),
                 data.frame(signer = au$signer, metric = "Verified entries per second", value = au$verify_entries_per_s),
                 data.frame(signer = au$signer, metric = "Bytes per log entry", value = au$bytes_per_entry))
au_long$metric <- factor(au_long$metric, levels = c("Signed entries per second", "Verified entries per second", "Bytes per log entry"))
p13a <- ggplot(au_long, aes(signer, value, fill = signer)) +
  geom_col(width = 0.6, show.legend = FALSE) +
  geom_text(aes(label = fmt_k(value)), vjust = -0.4, size = 4) +
  facet_wrap(~ metric, scales = "free_y") +
  scale_fill_manual(values = c("HMAC-SHA-512" = grey, "ML-DSA-65" = blue, "Ed25519 + ML-DSA-65 (dual)" = "#0B3D7A")) +
  scale_y_continuous(expand = expansion(mult = c(0, 0.15))) +
  labs(title = "Cost of a quantum-safe audit trail",
       subtitle = sprintf("One hash-chained entry per redaction, no PII stored. ML-DSA-65 costs %.1f ms per signed entry on this machine",
                          1000 / au$entries_per_s[au$signer == "ML-DSA-65"][1]),
       x = NULL, y = NULL)
p13a <- p13a + scale_x_discrete(labels = function(x) sub(" \\(dual\\)", "\n(dual)", sub(" \\+ ", " +\n", x)))
save_plot(p13a, "13_qs_audit_cost.png", 11, 5)

sym <- subset(read_qs("qs_symmetric.csv"), !is.na(mb_per_s))
p13b <- ggplot(sym, aes(reorder(algorithm, mb_per_s), mb_per_s)) +
  geom_col(width = 0.6, fill = blue) +
  geom_text(aes(label = paste0(round(mb_per_s), " MB/s")), hjust = -0.1, size = 4) +
  coord_flip() +
  scale_y_continuous(expand = expansion(mult = c(0, 0.25))) +
  labs(title = "Quantum-resilient symmetric crypto throughput",
       subtitle = "All rated Secure in Redbook Table 1-1. Python hashlib and vault, 1 MiB buffers;\nOpenSSL runs SHA and AES on the CPACF on-chip accelerator on s390x",
       x = NULL, y = "MB per second", caption = "For raw OpenSSL AES-256-GCM on CPACF see reports/evidence/ibmz_crypto_s390x.txt")
save_plot(p13b, "14_qs_symmetric.png", 9, 4.5)
