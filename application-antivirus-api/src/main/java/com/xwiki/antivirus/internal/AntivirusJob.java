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
package com.xwiki.antivirus.internal;

import java.util.*;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.model.reference.AttachmentReference;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.plugin.scheduler.AbstractJob;
import com.xpn.xwiki.web.Utils;
import com.xwiki.antivirus.AntivirusConfiguration;
import com.xwiki.antivirus.AntivirusEngine;
import com.xwiki.antivirus.AntivirusException;
import com.xwiki.antivirus.AntivirusLog;
import com.xwiki.antivirus.AntivirusReportSender;
import com.xwiki.antivirus.ScanResult;
import com.xwiki.licensing.Licensor;

/**
 * Periodically runs an antivirus scan on all attachments in the wiki.
 *
 * @version $Id$
 */
public class AntivirusJob extends AbstractJob {
    private static final Logger LOGGER = LoggerFactory.getLogger(AntivirusJob.class);

    @Override
    protected void executeJob(JobExecutionContext jobContext) throws JobExecutionException {
        XWikiContext context = getXWikiContext();

        AntivirusConfiguration antivirusConfiguration = Utils.getComponent(AntivirusConfiguration.class);
        if (!antivirusConfiguration.isEnabled()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Scheduled Antirvirus scan is skipped. Antivirus is disabled.");
            }
            return;
        }

        // Skip if license has expired.
        Licensor licensor = Utils.getComponent(Licensor.class);
        if (!licensor.hasLicensure(new DocumentReference(context.getMainXWiki(), "Antivirus", "ConfigurationClass"))) {
            LOGGER.warn("Scheduled Antivirus scan is skipped. "
                    + "No valid Antivirus license has been found. Please visit the 'Licenses' section in Administration.");
            return;
        }

        Date startDate = new Date();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Antivirus scheduled scan execution using engine [{}] has started...",
                    antivirusConfiguration.getDefaultEngineName());
        }

        // Get the configured antivirus engine.
        AntivirusEngine antivirus = null;
        try {
            antivirus = Utils.getComponent(AntivirusEngine.class, antivirusConfiguration.getDefaultEngineName());
        } catch (Exception e) {
            LOGGER.error("Failed to load antivirus engine [{}] for scheduled scan.",
                    antivirusConfiguration.getDefaultEngineName(), e);
            return;
        }

        // Note: preserve the addition order so that we have a nice report.
        Map<XWikiAttachment, Collection<String>> deletedInfectedAttachments = new LinkedHashMap<>();
        Map<XWikiAttachment, Collection<String>> deleteFailedInfectedAttachments = new LinkedHashMap<>();
        Map<XWikiAttachment, Exception> scanFailedAttachments = new LinkedHashMap<>();

        Collection<String> wikiIds = null;
        try {
            wikiIds = Utils.getComponent(WikiDescriptorManager.class).getAllIds();
        } catch (Exception e) {
            LOGGER.error("Failed to get the list of wikis to scan", e);
            return;
        }

        for (String wikiId : wikiIds) {
            scanWiki(wikiId, antivirus, deletedInfectedAttachments, deleteFailedInfectedAttachments,
                    scanFailedAttachments);
        }

        Date endDate = new Date();

        // Send the report by email, if needed.
        maybeSendReport(deletedInfectedAttachments, deleteFailedInfectedAttachments, scanFailedAttachments, startDate,
                endDate);

        // Log the incidents in the Antivirus Log.
        logIncidents(deletedInfectedAttachments, deleteFailedInfectedAttachments,
                antivirusConfiguration.getDefaultEngineName());

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Antivirus scheduled scan execution using engine [{}] has finished.",
                    antivirusConfiguration.getDefaultEngineName());
        }
    }

    private void scanWiki(String wikiId, AntivirusEngine antivirus,
                          Map<XWikiAttachment, Collection<String>> deletedInfectedAttachments,
                          Map<XWikiAttachment, Collection<String>> deleteFailedInfectedAttachments,
                          Map<XWikiAttachment, Exception> scanFailedAttachments) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Scanning wiki [{}]...", wikiId);
        }

        // Get the list of scannable documents, that contain attachments.
        List<String> docsWithAttachments = null;
        QueryManager queryManager = Utils.getComponent(QueryManager.class);
        try {
            Query query = queryManager
                    .createQuery("SELECT DISTINCT doc.fullName FROM XWikiDocument AS doc, XWikiAttachment AS attachment "
                            + "WHERE doc.id = attachment.docId ORDER BY doc.fullName", Query.HQL)
                    .setWiki(wikiId);
            docsWithAttachments = query.execute();
        } catch (Exception e) {
            LOGGER.error("Failed to get the list of documents with attachments to scan for wiki [{}]", wikiId, e);
            return;
        }

        // Scan the documents and get the results.
        DocumentReferenceResolver<String> resolver = Utils.getComponent(DocumentReferenceResolver.TYPE_STRING);
        WikiReference wikiReference = new WikiReference(wikiId);
        for (String docFullName : docsWithAttachments) {
            DocumentReference documentReference = resolver.resolve(docFullName, wikiReference);
            scanDocument(documentReference, antivirus, deletedInfectedAttachments, deleteFailedInfectedAttachments,
                    scanFailedAttachments);
        }
    }

    private void scanDocument(DocumentReference documentReference, AntivirusEngine antivirus,
                              Map<XWikiAttachment, Collection<String>> deletedInfectedAttachments,
                              Map<XWikiAttachment, Collection<String>> deleteFailedInfectedAttachments,
                              Map<XWikiAttachment, Exception> scanFailedAttachments) {
        XWikiContext context = getXWikiContext();
        XWiki xwiki = context.getWiki();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Scanning document [{}]...", documentReference);
        }

        XWikiDocument document = null;
        try {
            document = xwiki.getDocument(documentReference, context);
        } catch (Exception e) {
            LOGGER.error("Failed to scan attachments of document [{}]", documentReference, e);
            return;
        }

        Map<XWikiAttachment, Collection<String>> deletedAttachmentsForDoc = new HashMap<>();

        // Used for logging.
        Map<String, Collection<String>> loggingData = new HashMap<>();

        // Use a clone while iterating to avoid ConcurrentModificationExceptions while removing attachments.
        List<XWikiAttachment> attachmentsList = new ArrayList<>(document.getAttachmentList());

        for (XWikiAttachment attachment : attachmentsList) {
            scanAttachment(attachment, antivirus, document, deletedAttachmentsForDoc, loggingData,
                    scanFailedAttachments);
        }

        // Save the changes, if needed.
        if (deletedAttachmentsForDoc.isEmpty()) {
            return;
        }

        try {
            // Use the (scheduler job's) context user as author.
            document.setAuthorReference(context.getUserReference());

            xwiki.saveDocument(document, "[Antivirus Application] Automatically removed infected attachment(s)",
                    context);

            // Log and add to the successful deletions report.
            LOGGER.warn("Deleted infected attachments from document [{}]: [{}]", document.getDocumentReference(),
                    loggingData);
            deletedInfectedAttachments.putAll(deletedAttachmentsForDoc);
        } catch (Exception e) {
            // Log and add to the failed deletions report.
            LOGGER.error("Failed to delete infected attachments from document [{}]: [{}]",
                    document.getDocumentReference(), loggingData, e);
            deleteFailedInfectedAttachments.putAll(deletedAttachmentsForDoc);
        }
    }

    private void scanAttachment(XWikiAttachment attachment, AntivirusEngine antivirus, XWikiDocument document,
                                Map<XWikiAttachment, Collection<String>> deletedAttachmentsForDoc, Map<String, Collection<String>> loggingData,
                                Map<XWikiAttachment, Exception> scanFailedAttachments) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Scanning attachment [{}]...", attachment.getReference());
        }

        ScanResult scanResult = null;
        try {
            scanResult = antivirus.scan(attachment);
            if (scanResult.isClean()) {
                return;
            }
        } catch (Exception e) {
            // Log the exception.
            LOGGER.error("Failed to scan attachment [{}]", attachment.getReference(), e);
            // Files larger than the ClamAV configured size (default 25MB) will fail to be scanned. Attempting to scan
            // will throw the following errors. In the scan report we want to display a user friendly message, so we
            // create a new exception.
            String rootExceptionMessage = ExceptionUtils.getRootCauseMessage(e);
            List<String> knownErrors = Arrays.asList(
                    "IOException: Broken pipe",
                    "ScanFailureException: Scan failure: INSTREAM size limit exceeded. ERROR");
            if (knownErrors.contains(rootExceptionMessage)) {
                e = new AntivirusException("File size too large");
            }
            // Add it to the list of failed attachments, to be sent in the report.
            scanFailedAttachments.put(attachment, e);
            // Nothing more to do for this attachment.
            return;
        }

        // Remove the infected attachment, without sending it to the RecycleBin.
        document.removeAttachment(attachment, false);

        // Remember the removed attachments for the current document.
        deletedAttachmentsForDoc.put(attachment, scanResult.getfoundViruses());

        // Extract the relevant logging data.
        loggingData.put(attachment.getFilename(), scanResult.getfoundViruses());
    }

    private void maybeSendReport(Map<XWikiAttachment, Collection<String>> deletedInfectedAttachments,
                                 Map<XWikiAttachment, Collection<String>> deleteFailedInfectedAttachments,
                                 Map<XWikiAttachment, Exception> scanFailedAttachments, Date startDate, Date endDate) {
        AntivirusConfiguration antivirusConfiguration = Utils.getComponent(AntivirusConfiguration.class);

        // Skip sending the report only when no infected attachments are found and report sending is not forced.
        if (!antivirusConfiguration.shouldAlwaysSendReport() && deletedInfectedAttachments.isEmpty()
                && deleteFailedInfectedAttachments.isEmpty()) {
            LOGGER.debug("No-infections scheduled scan report sending is skipped. 'Alway Send Report' is disabled.");
            return;
        }

        try {
            AntivirusReportSender reportSender = Utils.getComponent(AntivirusReportSender.class);
            reportSender.sendReport(deletedInfectedAttachments, deleteFailedInfectedAttachments, scanFailedAttachments,
                    startDate, endDate);
        } catch (Exception e) {
            // XWikiAttachment.toString() is not very useful when logging, so we need something better.
            Map<AttachmentReference, Collection<String>> failed =
                    getLoggingFriendlyMap(deleteFailedInfectedAttachments);
            Map<AttachmentReference, Collection<String>> deleted = getLoggingFriendlyMap(deletedInfectedAttachments);
            LOGGER.error(
                    "Failed to send the infection report. Logging the report instead...\n"
                            + "Delete failed for infected attachments: [{}]\n" + "Deleted infected attachments: [{}]\n"
                            + "Scan failed attachments: [{}]\n" + "Start date: [{}]\n" + "End date: [{}]",
                    failed, deleted, scanFailedAttachments, startDate, endDate);
        }
    }

    private Map<AttachmentReference, Collection<String>> getLoggingFriendlyMap(
            Map<XWikiAttachment, Collection<String>> xwikiAttachmentMap) {
        Map<AttachmentReference, Collection<String>> attachmentReferenceMap = new LinkedHashMap<>();
        for (Map.Entry<XWikiAttachment, Collection<String>> entry : xwikiAttachmentMap.entrySet()) {
            attachmentReferenceMap.put(entry.getKey().getReference(), entry.getValue());
        }

        return attachmentReferenceMap;
    }

    private void logIncidents(Map<XWikiAttachment, Collection<String>> deletedInfectedAttachments,
                              Map<XWikiAttachment, Collection<String>> deleteFailedInfectedAttachments, String engineHint) {
        AntivirusLog antivirusLog = Utils.getComponent(AntivirusLog.class);

        logIncidents(antivirusLog, deletedInfectedAttachments, "deleted", engineHint);
        logIncidents(antivirusLog, deleteFailedInfectedAttachments, "deleteFailed", engineHint);
    }

    private void logIncidents(AntivirusLog antivirusLog, Map<XWikiAttachment, Collection<String>> infectedAttachments,
                              String action, String engineHint) {
        for (Map.Entry<XWikiAttachment, Collection<String>> entry : infectedAttachments.entrySet()) {
            try {
                antivirusLog.log(entry.getKey(), entry.getValue(), action, "scheduledScan", engineHint);
            } catch (AntivirusException e) {
                LOGGER.error("Failed to log scheduled scan incident", e);
            }
        }
    }
}
