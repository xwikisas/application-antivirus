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

import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.xwiki.component.annotation.Role;

import com.xpn.xwiki.doc.XWikiAttachment;

/**
 * Sends the result of an antivirus scheduled scan as a report to the wiki admins.
 *
 * @version $Id$
 */
@Role
public interface AntivirusReportSender
{
    /**
     * @param deletedInfectedAttachments map of [attachment,list of infections] for each deleted infected attachment
     * @param deleteFailedInfectedAttachments map of [attachment,list of infections] for each infected attachment for
     *            which deletion failed
     * @param scanFailedAttachments map of [attachment,exception] for each attachment that failed to be scanned
     * @param startDate when the scheduled scan started
     * @param endDate when the scheduled scan ended
     * @throws Exception in case of problems
     */
    void sendReport(Map<XWikiAttachment, Collection<String>> deletedInfectedAttachments,
        Map<XWikiAttachment, Collection<String>> deleteFailedInfectedAttachments,
        Map<XWikiAttachment, Exception> scanFailedAttachments, Date startDate, Date endDate) throws Exception;
}
