# Charts for the PII redaction evaluation. Reads reports/figures_data/*.csv,
# writes reports/figures/*.png. Run from the project root:
#   Rscript r/plot_metrics.R
suppressPackageStartupMessages(library(ggplot2))
options(bitmapType = "cairo")

data_dir <- "reports/figures_data"
out_dir  <- "reports/figures"
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)
theme_set(theme_minimal(base_size = 13))
pal <- c(regex = "#9AA5B1", ml = "#6C8EBF", hybrid = "#1F5FAD")
pct <- function(x) paste0(round(100 * x), "%")

save_plot <- function(p, name, w = 8, h = 5) {
  ggsave(file.path(out_dir, name), p, width = w, height = h, dpi = 150, bg = "white")
  cat("saved", file.path(out_dir, name), "\n")
}

# 1. Headline: share of PII characters redacted
cov <- read.csv(file.path(data_dir, "coverage_by_detector.csv"))
cov$detector <- factor(cov$detector, levels = c("regex", "ml", "hybrid"))
p1 <- ggplot(cov, aes(detector, coverage, fill = detector)) +
  geom_col(width = 0.6, show.legend = FALSE) +
  geom_text(aes(label = sprintf("%.1f%%", 100 * coverage)), vjust = -0.5, size = 5) +
  scale_fill_manual(values = pal) +
  scale_y_continuous(labels = pct, limits = c(0, 1.08)) +
  labs(title = "Share of annotated PII characters redacted",
       subtitle = "Validation set, 6,987 documents", x = NULL, y = NULL)
save_plot(p1, "01_coverage_by_detector.png", 7, 5)

# 2. Overlap F1 by PII type
f1 <- subset(read.csv(file.path(data_dir, "f1_by_type.csv")), match == "overlap")
f1$detector <- factor(f1$detector, levels = c("regex", "ml", "hybrid"))
p2 <- ggplot(f1, aes(reorder(type, f1), f1, fill = detector)) +
  geom_col(position = position_dodge(preserve = "single"), width = 0.75) +
  scale_fill_manual(values = pal) +
  scale_y_continuous(limits = c(0, 1)) +
  coord_flip() +
  labs(title = "Overlap F1 by PII type",
       subtitle = "Regex was only scored on EMAIL, PHONE and NAME",
       x = NULL, y = "F1", fill = "Detector")
save_plot(p2, "02_f1_by_type.png", 8, 6)

# 3. Threshold trade-off
thr <- read.csv(file.path(data_dir, "threshold_tradeoff.csv"))
p3 <- ggplot(thr, aes(recall, precision)) +
  geom_path(colour = "#1F5FAD") +
  geom_point(size = 3, colour = "#1F5FAD") +
  geom_text(aes(label = paste("t =", threshold)), vjust = -1.1, size = 4) +
  scale_x_continuous(labels = pct, expand = expansion(mult = 0.15)) +
  scale_y_continuous(labels = pct, expand = expansion(mult = 0.15)) +
  labs(title = "Recall vs precision by redaction threshold",
       subtitle = "Higher threshold = fewer leaks, more over-redaction (dev split, token level)",
       x = "Recall (PII caught)", y = "Precision")
save_plot(p3, "03_threshold_tradeoff.png", 7, 5)

# 4. Coverage by dataset label: regex vs hybrid
lab <- read.csv(file.path(data_dir, "coverage_by_label.csv"))
lab$detector <- factor(lab$detector, levels = c("regex", "hybrid"))
p4 <- ggplot(lab, aes(reorder(label, coverage), coverage, fill = detector)) +
  geom_col(position = "dodge", width = 0.75) +
  scale_fill_manual(values = pal) +
  scale_y_continuous(labels = pct, limits = c(0, 1)) +
  coord_flip() +
  labs(title = "PII coverage by dataset label",
       x = NULL, y = "Entities touched by a detection", fill = "Detector")
save_plot(p4, "04_coverage_by_label.png", 8, 8)

# 5. Token classifier, dev split, per group
dev <- read.csv(file.path(data_dir, "dev_by_group.csv"))
dev$metric <- factor(dev$metric, levels = c("precision", "recall", "f1"))
p5 <- ggplot(dev, aes(reorder(group, value), value, fill = metric)) +
  geom_col(position = "dodge", width = 0.75) +
  scale_fill_manual(values = c(precision = "#9AA5B1", recall = "#6C8EBF", f1 = "#1F5FAD")) +
  coord_flip(ylim = c(0.7, 1)) +
  labs(title = "Token classifier per PII group",
       subtitle = "Dev split, 2,608 documents (axis starts at 0.70)",
       x = NULL, y = NULL, fill = NULL)
save_plot(p5, "05_dev_by_group.png", 8, 6)
