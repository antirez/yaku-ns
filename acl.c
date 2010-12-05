/* acl.c
 * Access Control List
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license version 2
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <string.h>
#include <stdlib.h>

/* global vars */

/* ACL chains, allow and deny lists for different targets */
struct acl *acl_dns_allow_head = NULL;
struct acl *acl_dns_allow_tail = NULL;
struct acl *acl_dns_deny_head = NULL;
struct acl *acl_dns_deny_tail = NULL;
struct acl *acl_fwd_allow_head = NULL;
struct acl *acl_fwd_allow_tail = NULL;
struct acl *acl_fwd_deny_head = NULL;
struct acl *acl_fwd_deny_tail = NULL;
struct acl *acl_axfr_allow_head = NULL;
struct acl *acl_axfr_allow_tail = NULL;
struct acl *acl_axfr_deny_head = NULL;
struct acl *acl_axfr_deny_tail = NULL;

/* not exported functions */
static int acl_check(char *ip, struct acl *allow, struct acl *deny);
static void acl_free_list(struct acl **head, struct acl **tail);

/* exported functions */
void acl_add_rule(char *rule, struct acl **head, struct acl **tail);
void acl_free(void);
int acl_check_dns(char *ip);
int acl_check_fwd(char *ip);
int acl_check_axfr(char *ip);

/* acl_add_rule() allocate and set a rule in the
 * acl list identified by 'head' and 'tail' */
void acl_add_rule(char *rule, struct acl **head, struct acl **tail)
{
	if (*head == NULL) {
		*head = malloc(sizeof(struct acl));
		if (*head == NULL)
			goto out_of_memory;
		*tail = *head;
	} else {
		(*tail)->next = malloc(sizeof(struct acl));
		if ((*tail)->next == NULL)
			goto out_of_memory;
		*tail = (*tail)->next;
	}
	strlcpy((*tail)->rule, rule, RULE_MAXSIZE);
	(*tail)->next = NULL;
	return;

out_of_memory:
	perror("acl_dns_add_rule() malloc");
	exit(1);
}

int acl_check_dns(char *ip)
{
	return acl_check(ip, acl_dns_allow_head, acl_dns_deny_head);
}

int acl_check_fwd(char *ip)
{
	return acl_check(ip, acl_fwd_allow_head, acl_fwd_deny_head);
}

int acl_check_axfr(char *ip)
{
	return acl_check(ip, acl_axfr_allow_head, acl_axfr_deny_head);
}

/* acl_check() implements the hosts.allow/hosts.deny style ACL */
static int acl_check(char *ip, struct acl *allow, struct acl *deny)
{
	struct acl *a;
	size_t l;

	a = allow; /* search in the allow list */
	while(a) {
		l = strlen(a->rule);
		if (a->rule[l-1] != '$') {
			if (!strncmp(a->rule, ip, l))
				return ACL_ALLOW;
		} else {
			if (l == 1) /* only $ */
				return ACL_ALLOW;
			if (l == strlen(ip)+1 && !strncmp(a->rule, ip, l-1))
				return ACL_ALLOW;
		}
		a = a->next;
	}

	a = deny; /* search in the deny list */
	while(a) {
		l = strlen(a->rule);
		if (a->rule[l-1] != '$') {
			if (!strncmp(a->rule, ip, l))
				return ACL_DENY;
		} else {
			if (l == 1) /* only $ */
				return ACL_DENY;
			if (l == strlen(ip)+1 && !strncmp(a->rule, ip, l-1))
				return ACL_DENY;
		}
		a = a->next;
	}
	return ACL_ALLOW;
}

/* Free all elements of some ACL list */
static void acl_free_list(struct acl **head, struct acl **tail)
{
	struct acl *a, *t;

	a = *head;
	while(a) {
		t = a->next;
		free(a);
		a = t;
	};
	*head = *tail = NULL;
}

/* Free all the ACL lists */
void acl_free(void)
{
	/* free the ACL list */
	acl_free_list(&acl_dns_allow_head, &acl_dns_allow_tail);
	acl_free_list(&acl_dns_deny_head, &acl_dns_deny_tail);
	acl_free_list(&acl_fwd_allow_head, &acl_axfr_allow_tail);
	acl_free_list(&acl_fwd_deny_head, &acl_axfr_deny_tail);
	acl_free_list(&acl_axfr_allow_head, &acl_axfr_allow_tail);
	acl_free_list(&acl_axfr_deny_head, &acl_axfr_deny_tail);
}
