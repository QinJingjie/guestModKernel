#define LBR_ENTRIES 4
#define IA32_DEBUGCTL_LBR			1UL << 0
#define LBR_SKIP 3
#define LBR_SELECT 0x1
#define LBR_FROM(from) (uint64_t)((((int64_t)from) << LBR_SKIP) >> LBR_SKIP)

struct lbr_t {
    uint64_t debug;   // contents of IA32_DEBUGCTL MSR
    uint64_t select;  // contents of LBR_SELECT
    uint64_t tos;     // index to most recent branch entry
    uint64_t from[LBR_ENTRIES];
    uint64_t   to[LBR_ENTRIES];
    struct task_struct *task; // pointer to the task_struct this state belongs to
};

void dump_lbr(struct lbr_t *lbr);
void enable_lbr(void);
void get_lbr(struct lbr_t *lbr);