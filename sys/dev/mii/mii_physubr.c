/*	$NetBSD: mii_physubr.c,v 1.101 2022/08/23 01:05:50 riastradh Exp $	*/

/*-
 * Copyright (c) 1998, 1999, 2000, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Subroutines common to all PHYs.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: mii_physubr.c,v 1.101 2022/08/23 01:05:50 riastradh Exp $");

#include <sys/param.h>
#include <sys/device.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/module.h>
#include <sys/module_hook.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/route.h>

#include <dev/dev_verbose.h>

#include <dev/mii/mii.h>
#include <dev/mii/miidevs.h>
#include <dev/mii/miivar.h>

DEV_VERBOSE_DEFINE(mii);

const char *
mii_get_descr(char *descr, size_t len, uint32_t oui, uint32_t model)
{
	char temp[MII_MAX_DESCR_LEN];

	mii_load_verbose();
	if (miiverbose_loaded) {
		if (mii_findvendor(temp, sizeof(temp), oui) == NULL) {
			descr[0] = '\0';
			return NULL;
		}
		strlcpy(descr, temp, len);
		strlcat(descr, " ", len);
		if (mii_findproduct(temp, sizeof(temp), oui, model) == NULL) {
			descr[0] = '\0';
			return NULL;
		}
		strlcat(descr, temp, len);
		return descr;
	}
	snprintf(descr, len, "OUI 0x%06x model 0x%04x", oui, model);
	return NULL;
}

static void mii_phy_statusmsg(struct mii_softc *);

/*
 * Media to register setting conversion table.  Order matters.
 */
static const struct mii_media mii_media_table[MII_NMEDIA] = {
	/* None */
	{ BMCR_ISO,		ANAR_CSMA,
	  0, },

	/* 10baseT */
	{ BMCR_S10,		ANAR_CSMA | ANAR_10,
	  0, },

	/* 10baseT-FDX */
	{ BMCR_S10|BMCR_FDX,	ANAR_CSMA | ANAR_10_FD,
	  0, },

	/* 100baseT4 */
	{ BMCR_S100,		ANAR_CSMA | ANAR_T4,
	  0, },

	/* 100baseTX */
	{ BMCR_S100,		ANAR_CSMA | ANAR_TX,
	  0, },

	/* 100baseTX-FDX */
	{ BMCR_S100|BMCR_FDX,	ANAR_CSMA | ANAR_TX_FD,
	  0, },

	/* 1000baseX */
	{ BMCR_S1000,		ANAR_CSMA,
	  0, },

	/* 1000baseX-FDX */
	{ BMCR_S1000|BMCR_FDX,	ANAR_CSMA,
	  0, },

	/* 1000baseT */
	{ BMCR_S1000,		ANAR_CSMA,
	  GTCR_ADV_1000THDX },

	/* 1000baseT-FDX */
	{ BMCR_S1000,		ANAR_CSMA,
	  GTCR_ADV_1000TFDX },
};

static void	mii_phy_auto_timeout(void *);
static void	mii_phy_auto_timeout_locked(struct mii_softc *);

void
mii_phy_setmedia(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	uint16_t bmcr, anar, gtcr;

	KASSERT(mii_locked(mii));

	if (IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO) {
		/*
		 * Force renegotiation if MIIF_DOPAUSE.
		 *
		 * XXX This is only necessary because many NICs don't
		 * XXX advertise PAUSE capabilities at boot time.  Maybe
		 * XXX we should force this only once?
		 */
		PHY_READ(sc, MII_BMCR, &bmcr);
		if ((bmcr & BMCR_AUTOEN) == 0 ||
		    (sc->mii_flags & (MIIF_FORCEANEG | MIIF_DOPAUSE)))
			(void) mii_phy_auto(sc);
		return;
	}

	/* Table index is stored in the media entry. */

#ifdef DIAGNOSTIC
	if (/* ife->ifm_data < 0 || */ ife->ifm_data >= MII_NMEDIA)
		panic("mii_phy_setmedia");
#endif

	anar = mii_media_table[ife->ifm_data].mm_anar;
	bmcr = mii_media_table[ife->ifm_data].mm_bmcr;
	gtcr = mii_media_table[ife->ifm_data].mm_gtcr;

	if (mii->mii_media.ifm_media & IFM_ETH_MASTER) {
		switch (IFM_SUBTYPE(ife->ifm_media)) {
		case IFM_1000_T:
			gtcr |= GTCR_MAN_MS | GTCR_ADV_MS;
			break;

		default:
			panic("mii_phy_setmedia: MASTER on wrong media");
		}
	}

	if (mii->mii_media.ifm_media & IFM_FLOW) {
		if (sc->mii_flags & MIIF_IS_1000X)
			anar |= ANAR_X_PAUSE_SYM | ANAR_X_PAUSE_ASYM;
		else {
			anar |= ANAR_FC;
			/* XXX Only 1000BASE-T has PAUSE_ASYM? */
			if ((sc->mii_flags & MIIF_HAVE_GTCR) &&
			    (sc->mii_extcapabilities &
			     (EXTSR_1000THDX | EXTSR_1000TFDX)))
				anar |= ANAR_PAUSE_ASYM;
		}
	}

	if (ife->ifm_media & IFM_LOOP)
		bmcr |= BMCR_LOOP;

	PHY_WRITE(sc, MII_ANAR, anar);
	if (sc->mii_flags & MIIF_HAVE_GTCR)
		PHY_WRITE(sc, MII_100T2CR, gtcr);
	if (IFM_SUBTYPE(ife->ifm_media) == IFM_1000_T)
		mii_phy_auto(sc);
	else
		PHY_WRITE(sc, MII_BMCR, bmcr);
}

/* Setup autonegotiation and start it. */
int
mii_phy_auto(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;

	KASSERT(mii_locked(mii));

	sc->mii_ticks = 0;
	if ((sc->mii_flags & MIIF_DOINGAUTO) == 0) {
		/*
		 * Check for 1000BASE-X.  Autonegotiation is a bit
		 * different on such devices.
		 */
		if (sc->mii_flags & MIIF_IS_1000X) {
			uint16_t anar = 0;

			if (sc->mii_extcapabilities & EXTSR_1000XFDX)
				anar |= ANAR_X_FD;
			if (sc->mii_extcapabilities & EXTSR_1000XHDX)
				anar |= ANAR_X_HD;

			if (sc->mii_flags & MIIF_DOPAUSE) {
				/* XXX Asymmetric vs. symmetric? */
				anar |= ANLPAR_X_PAUSE_TOWARDS;
			}

			PHY_WRITE(sc, MII_ANAR, anar);
		} else {
			uint16_t anar;

			anar = BMSR_MEDIA_TO_ANAR(sc->mii_capabilities) |
			    ANAR_CSMA;
			if (sc->mii_flags & MIIF_DOPAUSE) {
				anar |= ANAR_FC;
				/* XXX Only 1000BASE-T has PAUSE_ASYM? */
				if ((sc->mii_flags & MIIF_HAVE_GTCR) &&
				    (sc->mii_extcapabilities &
				     (EXTSR_1000THDX | EXTSR_1000TFDX)))
					anar |= ANAR_PAUSE_ASYM;
			}

			/*
			 *  For 1000-base-T, autonegotiation must be enabled,
			 * but if we're not set to auto, only advertise
			 * 1000-base-T with the link partner.
			 */
			if (IFM_SUBTYPE(ife->ifm_media) == IFM_1000_T) {
				anar &= ~(ANAR_T4 | ANAR_TX_FD | ANAR_TX |
				    ANAR_10_FD | ANAR_10);
			}

			PHY_WRITE(sc, MII_ANAR, anar);
			if (sc->mii_flags & MIIF_HAVE_GTCR) {
				uint16_t gtcr = 0;

				if (sc->mii_extcapabilities & EXTSR_1000TFDX)
					gtcr |= GTCR_ADV_1000TFDX;
				if (sc->mii_extcapabilities & EXTSR_1000THDX)
					gtcr |= GTCR_ADV_1000THDX;

				PHY_WRITE(sc, MII_100T2CR, gtcr);
			}
		}
		PHY_WRITE(sc, MII_BMCR, BMCR_AUTOEN | BMCR_STARTNEG);
	}

	/*
	 * Just let it finish asynchronously.  This is for the benefit of
	 * the tick handler driving autonegotiation.  Don't want 500ms
	 * delays all the time while the system is running!
	 */
	if (sc->mii_flags & MIIF_AUTOTSLEEP) {
		ASSERT_SLEEPABLE();
		sc->mii_flags |= MIIF_DOINGAUTO;
		kpause("miiaut", false, hz >> 1, mii->mii_media.ifm_lock);
		mii_phy_auto_timeout_locked(sc);
		KASSERT((sc->mii_flags & MIIF_DOINGAUTO) == 0);
		cv_broadcast(&sc->mii_nway_cv);
	} else if ((sc->mii_flags & MIIF_DOINGAUTO) == 0) {
		sc->mii_flags |= MIIF_DOINGAUTO;
		callout_reset(&sc->mii_nway_ch, hz >> 1,
		    mii_phy_auto_timeout, sc);
	}
	return EJUSTRETURN;
}

/* Just restart autonegotiation without changing any setting */
int
mii_phy_auto_restart(struct mii_softc *sc)
{
	uint16_t reg;

	PHY_READ(sc, MII_BMCR, &reg);
	reg |= BMCR_STARTNEG;
	PHY_WRITE(sc, MII_BMCR, reg);
	sc->mii_ticks = 0;

	return EJUSTRETURN;
}

static void
mii_phy_auto_timeout_locked(struct mii_softc *sc)
{

	KASSERT(mii_locked(sc->mii_pdata));
	KASSERT(sc->mii_flags & MIIF_DOINGAUTO);

	if (!device_is_active(sc->mii_dev))
		return;

	sc->mii_flags &= ~MIIF_DOINGAUTO;

	/* Update the media status. */
	(void) PHY_SERVICE(sc, sc->mii_pdata, MII_POLLSTAT);
}

static void
mii_phy_auto_timeout(void *arg)
{
	struct mii_softc *sc = arg;

	KASSERT((sc->mii_flags & MIIF_AUTOTSLEEP) == 0);

	if (!device_is_active(sc->mii_dev))
		return;

	mii_lock(sc->mii_pdata);
	mii_phy_auto_timeout_locked(sc);
	mii_unlock(sc->mii_pdata);
}

int
mii_phy_tick(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	uint16_t reg;

	KASSERT(mii_locked(mii));

	/* Just bail now if the interface is down. */
	if ((mii->mii_ifp->if_flags & IFF_UP) == 0)
		return EJUSTRETURN;

	/*
	 * If we're not doing autonegotiation, we don't need to do any extra
	 * work here.  However, we need to check the link status so we can
	 * generate an announcement by returning with 0 if the status changes.
	 */
	if ((IFM_SUBTYPE(ife->ifm_media) != IFM_AUTO) &&
	    (IFM_SUBTYPE(ife->ifm_media) != IFM_1000_T)) {
		/*
		 * Reset autonegotiation timer to 0 just to make sure
		 * the future autonegotiation start with 0.
		 */
		sc->mii_ticks = 0;
		return 0;
	}

	/* Read the status register twice; BMSR_LINK is latch-low. */
	PHY_READ(sc, MII_BMSR, &reg);
	PHY_READ(sc, MII_BMSR, &reg);
	if (reg & BMSR_LINK) {
		/*
		 * Reset autonegotiation timer to 0 in case the link
		 * goes down in the next tick.
		 */
		sc->mii_ticks = 0;
		/* See above. */
		return 0;
	}

	/*
	 * mii_ticks == 0 means it's the first tick after changing the media or
	 * the link became down since the last tick (see above), so return with
	 * 0 to update the status.
	 */
	if (sc->mii_ticks++ == 0)
		return 0;

	/*
	 * Only retry autonegotiation every N seconds.
	 */
	KASSERT(sc->mii_anegticks != 0);
	if (sc->mii_ticks <= sc->mii_anegticks)
		return EJUSTRETURN;

	if (mii_phy_auto_restart(sc) == EJUSTRETURN)
		return EJUSTRETURN;

	/*
	 * Might need to generate a status message if autonegotiation
	 * failed.
	 */
	return 0;
}

void
mii_phy_reset(struct mii_softc *sc)
{
	int i;
	uint16_t reg;

	KASSERT(mii_locked(sc->mii_pdata));

	if (sc->mii_flags & MIIF_NOISOLATE)
		reg = BMCR_RESET;
	else
		reg = BMCR_RESET | BMCR_ISO;
	PHY_WRITE(sc, MII_BMCR, reg);

	/* Wait another 500ms for it to complete. */
	for (i = 0; i < 500; i++) {
		PHY_READ(sc, MII_BMCR, &reg);
		if ((reg & BMCR_RESET) == 0)
			break;
		delay(1000);
	}

	if (sc->mii_inst != 0 && ((sc->mii_flags & MIIF_NOISOLATE) == 0))
		PHY_WRITE(sc, MII_BMCR, reg | BMCR_ISO);
}

void
mii_phy_down(struct mii_softc *sc)
{

	KASSERT(mii_locked(sc->mii_pdata));

	if (sc->mii_flags & MIIF_AUTOTSLEEP) {
		while (sc->mii_flags & MIIF_DOINGAUTO) {
			cv_wait(&sc->mii_nway_cv,
			    sc->mii_pdata->mii_media.ifm_lock);
		}
	} else {
		if ((sc->mii_flags & MIIF_DOINGAUTO) != 0 &&
		    callout_halt(&sc->mii_nway_ch,
			sc->mii_pdata->mii_media.ifm_lock) == 0) {
			/*
			 * The callout was scheduled, and we prevented
			 * it from running before it expired, so we are
			 * now responsible for clearing the flag.
			 */
			sc->mii_flags &= ~MIIF_DOINGAUTO;
		}
	}
	KASSERT((sc->mii_flags & MIIF_DOINGAUTO) == 0);
}

void
mii_phy_status(struct mii_softc *sc)
{

	KASSERT(mii_locked(sc->mii_pdata));
	PHY_STATUS(sc);
}

void
mii_phy_update(struct mii_softc *sc, int cmd)
{
	struct mii_data *mii = sc->mii_pdata;
	u_int mii_media_active;
	int   mii_media_status;

	KASSERT(mii_locked(mii));

	mii_media_active = mii->mii_media_active;
	mii_media_status = mii->mii_media_status;

	if (sc->mii_media_active != mii_media_active ||
	    sc->mii_media_status != mii_media_status ||
	    cmd == MII_MEDIACHG) {
		mii_phy_statusmsg(sc);
		(*mii->mii_statchg)(mii->mii_ifp);
		sc->mii_media_active = mii_media_active;
		sc->mii_media_status = mii_media_status;
	}
}

static void
mii_phy_statusmsg(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	struct ifnet *ifp = mii->mii_ifp;

	KASSERT(mii_locked(mii));

	if (mii->mii_media_status & IFM_AVALID) {
		if (mii->mii_media_status & IFM_ACTIVE)
			if_link_state_change(ifp, LINK_STATE_UP);
		else
			if_link_state_change(ifp, LINK_STATE_DOWN);
	} else
		if_link_state_change(ifp, LINK_STATE_UNKNOWN);

	/* XXX NET_MPSAFE */
	ifp->if_baudrate = ifmedia_baudrate(mii->mii_media_active);
}

/*
 * Initialize generic PHY media based on BMSR, called when a PHY is
 * attached.  We expect to be set up to print a comma-separated list
 * of media names.  Does not print a newline.
 */
void
mii_phy_add_media(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	device_t self = sc->mii_dev;
	const char *sep = "";
	int fdx = 0;

	aprint_normal_dev(self, "");
	if ((sc->mii_capabilities & BMSR_MEDIAMASK) == 0 &&
	    (sc->mii_extcapabilities & EXTSR_MEDIAMASK) == 0) {
		aprint_error("no media present\n");
		goto out;
	}

	/*
	 * Set the autonegotiation timer for 10/100 media.  Gigabit media is
	 * handled below.
	 */
	mii_lock(mii);
	sc->mii_anegticks = MII_ANEGTICKS;
	mii_unlock(mii);

#define	ADD(m, c)	ifmedia_add(&mii->mii_media, (m), (c), NULL)
#define	PRINT(n)	aprint_normal("%s%s", sep, (n)); sep = ", "

	/* This flag is static; no need to lock. */
	if ((sc->mii_flags & MIIF_NOISOLATE) == 0)
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_NONE, 0, sc->mii_inst),
		    MII_MEDIA_NONE);

	/*
	 * There are different interpretations for the bits in
	 * HomePNA PHYs.  And there is really only one media type
	 * that is supported.  This flag is also static, and so
	 * no need to lock.
	 */
	if (sc->mii_flags & MIIF_IS_HPNA) {
		if (sc->mii_capabilities & BMSR_10THDX) {
			ADD(IFM_MAKEWORD(IFM_ETHER, IFM_HPNA_1, 0,
					 sc->mii_inst),
			    MII_MEDIA_10_T);
			PRINT("HomePNA1");
		}
		goto out;
	}

	if (sc->mii_capabilities & BMSR_10THDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_10_T, 0, sc->mii_inst),
		    MII_MEDIA_10_T);
		PRINT("10baseT");
	}
	if (sc->mii_capabilities & BMSR_10TFDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_10_T, IFM_FDX, sc->mii_inst),
		    MII_MEDIA_10_T_FDX);
		PRINT("10baseT-FDX");
		fdx = 1;
	}
	if (sc->mii_capabilities & BMSR_100TXHDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_100_TX, 0, sc->mii_inst),
		    MII_MEDIA_100_TX);
		PRINT("100baseTX");
	}
	if (sc->mii_capabilities & BMSR_100TXFDX) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_100_TX, IFM_FDX, sc->mii_inst),
		    MII_MEDIA_100_TX_FDX);
		PRINT("100baseTX-FDX");
		fdx = 1;
	}
	if (sc->mii_capabilities & BMSR_100T4) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_100_T4, 0, sc->mii_inst),
		    MII_MEDIA_100_T4);
		PRINT("100baseT4");
	}

	if (sc->mii_extcapabilities & EXTSR_MEDIAMASK) {
		/*
		 * XXX Right now only handle 1000SX and 1000TX.  Need
		 * XXX to handle 1000LX and 1000CX some how.
		 *
		 * Note since it can take 5 seconds to auto-negotiate
		 * a gigabit link, we make anegticks 10 seconds for
		 * all the gigabit media types.
		 */
		if (sc->mii_extcapabilities & EXTSR_1000XHDX) {
			mii_lock(mii);
			sc->mii_anegticks = MII_ANEGTICKS_GIGE;
			sc->mii_flags |= MIIF_IS_1000X;
			mii_unlock(mii);
			ADD(IFM_MAKEWORD(IFM_ETHER, IFM_1000_SX, 0,
			    sc->mii_inst), MII_MEDIA_1000_X);
			PRINT("1000baseSX");
		}
		if (sc->mii_extcapabilities & EXTSR_1000XFDX) {
			mii_lock(mii);
			sc->mii_anegticks = MII_ANEGTICKS_GIGE;
			sc->mii_flags |= MIIF_IS_1000X;
			mii_unlock(mii);
			ADD(IFM_MAKEWORD(IFM_ETHER, IFM_1000_SX, IFM_FDX,
			    sc->mii_inst), MII_MEDIA_1000_X_FDX);
			PRINT("1000baseSX-FDX");
			fdx = 1;
		}

		/*
		 * 1000baseT media needs to be able to manipulate
		 * master/slave mode.  We set IFM_ETH_MASTER in
		 * the "don't care mask" and filter it out when
		 * the media is set.
		 *
		 * All 1000baseT PHYs have a 1000baseT control register.
		 */
		if (sc->mii_extcapabilities & EXTSR_1000THDX) {
			mii_lock(mii);
			sc->mii_anegticks = MII_ANEGTICKS_GIGE;
			sc->mii_flags |= MIIF_HAVE_GTCR;
			mii->mii_media.ifm_mask |= IFM_ETH_MASTER;
			mii_unlock(mii);
			ADD(IFM_MAKEWORD(IFM_ETHER, IFM_1000_T, 0,
			    sc->mii_inst), MII_MEDIA_1000_T);
			PRINT("1000baseT");
		}
		if (sc->mii_extcapabilities & EXTSR_1000TFDX) {
			mii_lock(mii);
			sc->mii_anegticks = MII_ANEGTICKS_GIGE;
			sc->mii_flags |= MIIF_HAVE_GTCR;
			mii->mii_media.ifm_mask |= IFM_ETH_MASTER;
			mii_unlock(mii);
			ADD(IFM_MAKEWORD(IFM_ETHER, IFM_1000_T, IFM_FDX,
			    sc->mii_inst), MII_MEDIA_1000_T_FDX);
			PRINT("1000baseT-FDX");
			fdx = 1;
		}
	}

	if (sc->mii_capabilities & BMSR_ANEG) {
		ADD(IFM_MAKEWORD(IFM_ETHER, IFM_AUTO, 0, sc->mii_inst),
		    MII_NMEDIA);	/* intentionally invalid index */
		PRINT("auto");
	}
#undef ADD
#undef PRINT
	/* This flag is static; no need to lock. */
	if (fdx != 0 && (sc->mii_flags & MIIF_DOPAUSE)) {
		mii_lock(mii);
		mii->mii_media.ifm_mask |= IFM_ETH_FMASK;
		mii_unlock(mii);
	}
out:
	aprint_normal("\n");
	if (!pmf_device_register(self, NULL, mii_phy_resume)) {
		aprint_error_dev(self, "couldn't establish power handler\n");
	}
}

void
mii_phy_delete_media(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;

	ifmedia_delete_instance(&mii->mii_media, sc->mii_inst);
}

int
mii_phy_activate(device_t self, enum devact act)
{

	switch (act) {
	case DVACT_DEACTIVATE:
		/* XXX Invalidate parent's media setting? */
		return 0;
	default:
		return EOPNOTSUPP;
	}
}

/* ARGSUSED1 */
int
mii_phy_detach(device_t self, int flags)
{
	struct mii_softc *sc = device_private(self);

	/* No mii_lock because mii_flags should be stable by now.  */
	KASSERT((sc->mii_flags & MIIF_DOINGAUTO) == 0);

	if (sc->mii_flags & MIIF_AUTOTSLEEP)
		cv_destroy(&sc->mii_nway_cv);
	else
		callout_destroy(&sc->mii_nway_ch);

	mii_phy_delete_media(sc);

	return 0;
}

const struct mii_phydesc *
mii_phy_match(const struct mii_attach_args *ma, const struct mii_phydesc *mpd)
{

	for (; mpd->mpd_oui != 0; mpd++) {
		if (MII_OUI(ma->mii_id1, ma->mii_id2) == mpd->mpd_oui &&
		    MII_MODEL(ma->mii_id2) == mpd->mpd_model)
			return mpd;
	}
	return NULL;
}

/*
 * Return the flow control status flag from MII_ANAR & MII_ANLPAR.
 */
u_int
mii_phy_flowstatus(struct mii_softc *sc)
{
	uint16_t anar, anlpar;

	KASSERT(mii_locked(sc->mii_pdata));

	if ((sc->mii_flags & MIIF_DOPAUSE) == 0)
		return 0;

	PHY_READ(sc, MII_ANAR, &anar);
	PHY_READ(sc, MII_ANLPAR, &anlpar);

	/* For 1000baseX, the bits are in a different location. */
	if (sc->mii_flags & MIIF_IS_1000X) {
		anar <<= 3;
		anlpar <<= 3;
	}

	if ((anar & ANAR_PAUSE_SYM) & (anlpar & ANLPAR_PAUSE_SYM))
		return (IFM_FLOW | IFM_ETH_TXPAUSE | IFM_ETH_RXPAUSE);

	if ((anar & ANAR_PAUSE_SYM) == 0) {
		if ((anar & ANAR_PAUSE_ASYM) &&
		    ((anlpar & ANLPAR_PAUSE_TOWARDS) == ANLPAR_PAUSE_TOWARDS))
			return (IFM_FLOW | IFM_ETH_TXPAUSE);
		else
			return 0;
	}

	if ((anar & ANAR_PAUSE_ASYM) == 0) {
		if (anlpar & ANLPAR_PAUSE_SYM)
			return (IFM_FLOW | IFM_ETH_TXPAUSE | IFM_ETH_RXPAUSE);
		else
			return 0;
	}

	switch ((anlpar & ANLPAR_PAUSE_TOWARDS)) {
	case ANLPAR_PAUSE_NONE:
		return 0;

	case ANLPAR_PAUSE_ASYM:
		return (IFM_FLOW | IFM_ETH_RXPAUSE);

	default:
		return (IFM_FLOW | IFM_ETH_RXPAUSE | IFM_ETH_TXPAUSE);
	}
	/* NOTREACHED */
}

bool
mii_phy_resume(device_t dv, const pmf_qual_t *qual)
{
	struct mii_softc *sc = device_private(dv);

	mii_lock(sc->mii_pdata);
	PHY_RESET(sc);
	bool rv = PHY_SERVICE(sc, sc->mii_pdata, MII_MEDIACHG) == 0;
	mii_unlock(sc->mii_pdata);

	return rv;
}


/*
 * Given an ifmedia_entry, return the corresponding ANAR value.
 */
uint16_t
mii_anar(struct ifmedia_entry *ife)
{

#ifdef DIAGNOSTIC
	if (ife->ifm_data >= MII_NMEDIA)
		panic("mii_anar");
#endif

	return mii_media_table[ife->ifm_data].mm_anar;
}
