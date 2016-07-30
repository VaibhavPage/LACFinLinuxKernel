struct node{
	struct node* next;
	char fingerprint;
};

typedef struct node node;

int insertLL(node **, char);
int removeLL(node **, char);
int searchLL(node *, char); 

int addItem(char, int, int, int);   // For inserting the new items in filter
int lookupItemCuckoo(unsigned int);  // For item lookup
int removeItem(unsigned int, int(*lookup)(unsigned int));  // Deletion of item if exists(call to lookup is made to check membership)
int getLength(char *);  // Length of line
int getPosition1(unsigned int, int); // Get position i1 for item 
int getPosition2(int, char, int); // Get position i2 for item 
char fingerprint_function(char *);  // Contains logic for fingerprint creation
char generateFingerprint(unsigned int); // Generates fingerprint
void readFromFile(char*, int);
void printAtPos(int, int, int, int);
int lookupItemLACFNonPopular(unsigned int);
char* convertDecimalToStr(unsigned int); // converting decima value to string

#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

struct fib_alias {
	struct hlist_node	fa_list;
	struct fib_info		*fa_info;
	u8			fa_tos;
	u8			fa_type;
	u8			fa_state;
	u8			fa_slen;
	u32			tb_id;
	s16			fa_default;
	struct rcu_head		rcu;
};

#define FA_S_ACCESSED	0x01

/* Dont write on fa_state unless needed, to keep it shared on all cpus */
static inline void fib_alias_accessed(struct fib_alias *fa)
{
	if (!(fa->fa_state & FA_S_ACCESSED))
		fa->fa_state |= FA_S_ACCESSED;
}

/* Exported by fib_semantics.c */
void fib_release_info(struct fib_info *);
struct fib_info *fib_create_info(struct fib_config *cfg);
int fib_nh_match(struct fib_config *cfg, struct fib_info *fi);
int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event, u32 tb_id,
		  u8 type, __be32 dst, int dst_len, u8 tos, struct fib_info *fi,
		  unsigned int);
void rtmsg_fib(int event, __be32 key, struct fib_alias *fa, int dst_len,
	       u32 tb_id, const struct nl_info *info, unsigned int nlm_flags);

static inline void fib_result_assign(struct fib_result *res,
				     struct fib_info *fi)
{
	/* we used to play games with refcounts, but we now use RCU */
	res->fi = fi;
}

struct fib_prop {
	int	error;
	u8	scope;
};

extern const struct fib_prop fib_props[RTN_MAX + 1];

#endif /* _FIB_LOOKUP_H */
