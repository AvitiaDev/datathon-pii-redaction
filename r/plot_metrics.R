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
       subtitle = "Spain validation set, 6,987 documents, threshold 0.85", x = NULL, y = NULL)
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
       subtitle = "Higher threshold = fewer leaks, more over-redaction (dev split, token level; end-to-end sweep in 08)",
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

# 6. Hero chart for the slides: coverage and documents that still leak
lk <- read.csv(file.path(data_dir, "leak_by_detector.csv"))
lk <- subset(lk, detector != "ml")
lk$bar <- factor(ifelse(lk$detector == "regex", "Regex only",
               ifelse(lk$set == "spain", "Hybrid\nSpain", "Hybrid\nMexico\n(synthetic)")),
               levels = c("Regex only", "Hybrid\nSpain", "Hybrid\nMexico\n(synthetic)"))
hero <- rbind(
  data.frame(panel = "PII characters redacted\n(higher is better)", bar = lk$bar, value = lk$coverage,
             label = sprintf("%.1f%%", 100 * lk$coverage), det = lk$detector),
  data.frame(panel = "Documents with any PII leak\n(lower is better)", bar = lk$bar, value = lk$leak_rate,
             label = sprintf("%.1f%%", 100 * lk$leak_rate), det = lk$detector))
hero$panel <- factor(hero$panel, levels = unique(hero$panel))
p6 <- ggplot(hero, aes(bar, value, fill = det)) +
  geom_col(width = 0.65, show.legend = FALSE) +
  geom_text(aes(label = label), vjust = -0.35, size = 11, fontface = "bold") +
  facet_wrap(~panel) +
  scale_fill_manual(values = pal) +
  scale_y_continuous(labels = pct, limits = c(0, 1.15), breaks = c(0, .25, .5, .75, 1)) +
  labs(title = "Hybrid detector: from 98% of documents leaking to 18.7%",
       subtitle = "Spain: 6,987 AI4Privacy validation docs. Mexico: 400 synthetic docs. Threshold 0.85.",
       x = NULL, y = NULL) +
  theme_minimal(base_size = 24) +
  theme(strip.text = element_text(size = 26, face = "bold"),
        plot.title = element_text(size = 32, face = "bold"),
        axis.text.x = element_text(size = 20, face = "bold"),
        panel.grid.major.x = element_blank())
save_plot(p6, "06_hero.png", 12, 6.75)

# 7. Mexico (synthetic) leak rate per type, before vs after the A5 rules
mx <- read.csv(file.path(data_dir, "mx_before_after.csv"))
mx$stage <- factor(mx$stage, levels = c("before", "after"),
                   labels = c("Before Mexican rules", "After Mexican rules"))
p7 <- ggplot(mx, aes(reorder(type, leak_rate), leak_rate, fill = stage)) +
  geom_col(position = "dodge", width = 0.75) +
  geom_text(aes(label = pct(leak_rate)), position = position_dodge(0.75), hjust = -0.15, size = 3.8) +
  scale_fill_manual(values = c("#9AA5B1", "#1F5FAD")) +
  scale_y_continuous(labels = pct, limits = c(0, 1.12)) +
  coord_flip() +
  labs(title = "Mexico (synthetic): leak rate per PII type",
       subtitle = "Hybrid detector, 400 synthetic documents, threshold 0.85. Doc leak 100% -> 2.5%",
       x = NULL, y = "Entities leaked", fill = NULL) +
  theme(legend.position = "top")
save_plot(p7, "07_mx_before_after.png", 8, 6)

# 8. End-to-end threshold sweep: leak rate vs precision
sw <- read.csv(file.path(data_dir, "threshold_sweep.csv"))
sw$set <- factor(sw$set, levels = c("spain", "mx"), labels = c("Spain", "Mexico (synthetic)"))
sw$chosen <- sw$threshold == 0.85
p8 <- ggplot(sw, aes(micro_precision, leak_rate, colour = set)) +
  geom_path(linewidth = 1) +
  geom_point(aes(size = chosen, shape = chosen)) +
  geom_text(aes(label = paste("t =", threshold), fontface = ifelse(chosen, "bold", "plain")),
            vjust = -1.1, size = 4, show.legend = FALSE) +
  scale_size_manual(values = c(`FALSE` = 2.5, `TRUE` = 6), guide = "none") +
  scale_shape_manual(values = c(`FALSE` = 16, `TRUE` = 18), guide = "none") +
  scale_colour_manual(values = c("#1F5FAD", "#D9822B")) +
  scale_x_continuous(labels = pct, expand = expansion(mult = 0.12)) +
  scale_y_continuous(labels = pct, expand = expansion(mult = 0.15)) +
  labs(title = "Threshold sweep: documents leaking vs precision",
       subtitle = "Hybrid detector, end to end. Chosen operating point 0.85 (large marker)",
       x = "Precision (micro)", y = "Documents with any PII leak", colour = NULL) +
  theme(legend.position = "top")
save_plot(p8, "08_threshold_sweep.png", 8, 5.5)
