/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.antivirus;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiAttachment;

import org.xwiki.component.annotation.Role;
import org.xwiki.query.QueryException;
import org.xwiki.stability.Unstable;

import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * Logs an Antivirus incident.
 *
 * @version $Id$
 */
@Role
public interface AntivirusLog
{
    /**
     * Logs an incident.
     *
     * @param attachment the affected attachment
     * @param infections the infections detected for the attachment
     * @param action the action that was taken for the attachment (e.g. "blocked", "deleted", "deleteFailed",
     *     "scanFailed")
     * @param detectionContext the context in which the infection was detected (e.g. "upload", "scheduledScan")
     * @param engineHint the engine implementation hint used to detect the infections
     * @throws AntivirusException in case a problem occurs
     */
    void log(XWikiAttachment attachment, Collection<String> infections, String action, String detectionContext,
        String engineHint) throws AntivirusException;

    /**
     * Retrieves all the logged incidents that happened after a given date.
     *
     * @param date the date representing the lower bound of the incidents
     * @return the incidents that took place after the specified date, grouped by the incident action (e.g. "blocked",
     *     "deleted", "deleteFailed", "scanFailed")
     * @since 1.5
     */
    @Unstable
    Map<String, Map<XWikiAttachment, Collection<String>>> getIncidents(Date date) throws QueryException, XWikiException;
}
