/* signal.c
 *
 * Copyright (C) 2000,2001,2002 by Salvatore Sanfilippo
 * <antirez@invece.org>
 *
 * This code is under the GPL license version 2
 * See the COPYING file for more information
 */

/* ens.h must be included before all other includes */
#include "ens.h"

#include <signal.h>
#include <stdlib.h>

static volatile int signal_up = 0;
static volatile int signal_usr1 = 0;
static volatile int signal_usr2 = 0;

/* The signals handler:
 * for the signals that can't be handled here
 * just set the flag */
void signal_handler(int signum)
{
	switch(signum) {
	case SIGHUP:
		signal_up++;
		break;
	case SIGUSR1:
		signal_usr1++;
		break;
	case SIGUSR2:
		signal_usr2++;
		break;
	case SIGSEGV:
		log(VERB_FORCE, "SIGSEGV trapped -- INTERNAL ERROR\n");
		dump_state();
		abort();
		break;
	default:
		log(VERB_FORCE, "Signal %d trapped: exit\n", signum);
		exit(1);
	}
	install_signal_handler();
}

/* Handle the signals that can't be handled asyncronously */
int handle_signals(void)
{
	int count = 0;

	if (signal_up) {
		signal_up--;
		log(VERB_LOW, "SIGHUP trapped: read the config file\n");
		config_reset();
		config_read(configfile);
		count++;
	}

	if (signal_usr1) {
		signal_usr1--;
		dump_state();
		count++;
	}

	if (signal_usr2) {
		signal_usr2--;
		opt_forward = !opt_forward;
		log(VERB_LOW, "SIGUSR2 trapped, forwarding is %s\n",
			opt_forward ? "ON" : "OFF");
		fflush(logfp);
		count++;
	}

	return count;
}

/* Install the handlers */
void install_signal_handler(void)
{
	Signal(SIGHUP, signal_handler);
	Signal(SIGUSR1, signal_handler);
	Signal(SIGUSR2, signal_handler);
	Signal(SIGSEGV, signal_handler);
}

/* Portable signal() from R.Stevens,
 * modified to reset the handler */
void (*Signal(int signo, void (*func)(int)))(int)
{
	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0; /* So if set SA_RESETHAND is cleared */
	if (signo == SIGALRM)
	{
#ifdef SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;   /* SunOS 4.x */
#endif
	}
	else
	{
#ifdef SA_RESTART
		act.sa_flags |= SA_RESTART;     /* SVR4, 4.4BSD, Linux */
#endif
	}
	if (sigaction(signo, &act, &oact) == -1)
		return SIG_ERR;
	return (oact.sa_handler);
}

/* Block the given signal */
int signal_block(int sig)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, sig);
	return sigprocmask(SIG_BLOCK, &set, NULL);
}

/* Unblock the given signal */
int signal_unblock(int sig)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, sig);
	return sigprocmask(SIG_UNBLOCK, &set, NULL);
}
