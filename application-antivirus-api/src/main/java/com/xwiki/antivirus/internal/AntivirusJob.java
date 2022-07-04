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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.SchedulerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.environment.Environment;
import org.xwiki.model.reference.AttachmentReference;
import org.xwiki.model.reference.AttachmentReferenceResolver;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.plugin.scheduler.AbstractJob;
import com.xpn.xwiki.web.Utils;
import com.xwiki.antivirus.AntivirusConfiguration;
import com.xwiki.antivirus.AntivirusEngine;
import com.xwiki.antivirus.AntivirusException;
import com.xwiki.antivirus.AntivirusLog;
import com.xwiki.antivirus.AntivirusReportSender;
import com.xwiki.antivirus.AntivirusScan;
import com.xwiki.antivirus.ScanResult;
import com.xwiki.licensing.Licensor;

/**
 * Periodically runs an antivirus scan on all attachments in the wiki.
 *
 * @version $Id$
 */
public class AntivirusJob extends AbstractJob
{
    private static final String JOB_START_TIME_KEY = "startTime";

    private static final String SCANNED_FILES_NR_KEY = "filesScanned";

    private static final String LAST_ATTACHMENT_KEY = "lastDocument";

    private static final String PATH = "/jobs/status/antivirus/";

    private static final String PROPERTIES_FILE_NAME = "scan.properties";

    public static final String JOB_STATUS_FILE_PATH = PATH + PROPERTIES_FILE_NAME;

    private static final Logger LOGGER = LoggerFactory.getLogger(AntivirusJob.class);

    private int filesScanned = 0;

    private boolean shouldResume = false;

    @Override
    protected void executeJob(JobExecutionContext jobContext) throws JobExecutionException
    {
        // Make sure there are no two same Antivirus Jobs running at the same time. If the current job is not the
        // oldest running, return.
        try {
            List<JobExecutionContext> activeAntivirusJobs = jobContext.getScheduler()
                .getCurrentlyExecutingJobs()
                .stream()
                .filter(job -> job.getJobDetail().getKey().getName().matches("[\\w\\d]+:Antivirus\\.AntivirusJob_\\d+"))
                .collect(Collectors.toList());
            if (activeAntivirusJobs.size() > 1 && !activeAntivirusJobs.stream()
                .min(Comparator.comparing(JobExecutionContext::getFireTime)).get().equals(jobContext))
            {
                LOGGER.warn("Stopped Antivirus Job from execution as there was another instance already running!");
                return;
            }
        } catch (SchedulerException e) {
            throw new RuntimeException(e);
        }
        XWikiContext context = getXWikiContext();

        // Create a properties file to store information about the progress of this Job. If the file already exists
        // in the file system, this means that a previous Job didn't finish properly and the current job will resume
        // the scan rather than start from scratch.
        String propertiesFilePath = getPropertiesFilesPath();
        Properties scanProperties = getOrCreatePropertiesFile(propertiesFilePath);

        AntivirusConfiguration antivirusConfiguration = Utils.getComponent(AntivirusConfiguration.class);
        if (!antivirusConfiguration.isEnabled()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Scheduled Antivirus scan is skipped. Antivirus is disabled.");
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

        Date startDate = new Date(Long.parseLong(scanProperties.getProperty(JOB_START_TIME_KEY)));

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

        List<String> wikiIds = null;
        try {
            wikiIds = Utils.getComponent(WikiDescriptorManager.class).getAllIds().stream().sorted()
                .collect(Collectors.toList());
        } catch (Exception e) {
            LOGGER.error("Failed to get the list of wikis to scan", e);
            return;
        }
        AntivirusLog antivirusLog = Utils.getComponent(AntivirusLog.class);

        // Resume the scan from the subwiki where the last scanned Document resided. The subwiki is inferred from the
        // document reference stored in the properties file.
        int resumeIndex = 0;
        if (shouldResume) {
            AttachmentReference lastAttScannedRef = getLastAttachmentScannedReference(scanProperties);
            String previousScanWiki = lastAttScannedRef.getDocumentReference().getWikiReference().getName();
            resumeIndex = Collections.binarySearch(wikiIds, previousScanWiki);
            shouldResume = resumeIndex >= 0;
        }

        for (int i = resumeIndex < 0 ? -resumeIndex - 1 : resumeIndex; i < wikiIds.size(); i++) {
            scanWiki(wikiIds.get(i), antivirus, scanProperties, propertiesFilePath, antivirusLog,
                antivirusConfiguration.getDefaultEngineName());
        }

        Date endDate = new Date();

        // Send the report by email, if needed.
        maybeSendReport(startDate, endDate, antivirusLog);

        // Delete the properties file, indicating that the scan finished successfully.
        try {
            Files.delete(Paths.get(propertiesFilePath));
        } catch (IOException e) {
            LOGGER.warn("Antivirus Job Scan status file at [{}] could not be deleted when Job execution finished",
                propertiesFilePath, e);
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Antivirus scheduled scan execution using engine [{}] has finished.",
                antivirusConfiguration.getDefaultEngineName());
        }
    }

    private void scanWiki(String wikiId, AntivirusEngine antivirus, Properties scanProperties, String propertiesPath,
        AntivirusLog antivirusLog, String engineHint)
    {
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
        DocumentReferenceResolver<String> resolver = Utils.getComponent(DocumentReferenceResolver.TYPE_STRING);
        EntityReferenceSerializer<String> serializer = Utils.getComponent(EntityReferenceSerializer.TYPE_STRING);
        WikiReference wikiReference = new WikiReference(wikiId);
        // Resume the scan from the last successfully scanned document from the previous Job.
        List<DocumentReference> docRefs =
            docsWithAttachments.stream().map(docName -> resolver.resolve(docName, wikiReference))
                .collect(Collectors.toList());

        int resumeIndex = 0;
        if (shouldResume) {
            AttachmentReference lastAttScannedRef = getLastAttachmentScannedReference(scanProperties);
            resumeIndex = Collections.binarySearch(docRefs, lastAttScannedRef.getDocumentReference());
            shouldResume = resumeIndex >= 0;
        }
        for (int i = resumeIndex < 0 ? -resumeIndex - 1 : resumeIndex; i < docRefs.size(); i++) {
            // After every scanned Document, persist its reference and the total number of scanned files, until that
            // point.
            scanDocument(docRefs.get(i), antivirus, scanProperties, antivirusLog, engineHint, serializer,
                propertiesPath);
        }
    }

    private AttachmentReference getLastAttachmentScannedReference(Properties scanProperties)
    {
        String lastAttachmentScanned = scanProperties.getProperty(LAST_ATTACHMENT_KEY);
        AttachmentReferenceResolver<String> attachmentResolver =
            Utils.getComponent(AttachmentReferenceResolver.TYPE_STRING);
        AttachmentReference lastAttScannedRef = attachmentResolver.resolve(lastAttachmentScanned);
        return lastAttScannedRef;
    }

    private void scanDocument(DocumentReference documentReference, AntivirusEngine antivirus, Properties scanProperties,
        AntivirusLog antivirusLog, String engineHint, EntityReferenceSerializer<String> serializer,
        String propertiesPath)
    {
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

        // Use a clone while iterating to avoid ConcurrentModificationExceptions while removing attachments.
        List<XWikiAttachment> attachmentsList =
            new ArrayList<>(document.getAttachmentList()).stream()
                .sorted(Comparator.comparing(XWikiAttachment::getFilename)).collect(Collectors.toList());
        int resumeIndex = 0;
        if (shouldResume) {
            AttachmentReference lastAttScannedRef = getLastAttachmentScannedReference(scanProperties);
            resumeIndex = Collections.binarySearch(
                attachmentsList.stream().map(XWikiAttachment::getReference).collect(Collectors.toList()),
                lastAttScannedRef);
            resumeIndex = resumeIndex >= 0 ? resumeIndex + 1 : -resumeIndex - 1;
            shouldResume = false;
        }
        for (int i = resumeIndex; i < attachmentsList.size(); i++) {
            scanAttachment(attachmentsList.get(i), antivirus, document, scanProperties, antivirusLog, engineHint,
                propertiesPath, serializer);
        }
    }

    private void scanAttachment(XWikiAttachment attachment, AntivirusEngine antivirus, XWikiDocument document,
        Properties scanProperties, AntivirusLog antivirusLog, String engineHint, String propertiesPath,
        EntityReferenceSerializer<String> serializer)
    {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Scanning attachment [{}]...", attachment.getReference());
        }

        ScanResult scanResult = null;
        try {
            scanResult = antivirus.scan(attachment);
            scanProperties.setProperty(SCANNED_FILES_NR_KEY, String.valueOf(++filesScanned));
            if (scanResult.isClean()) {
                scanProperties.setProperty(LAST_ATTACHMENT_KEY, serializer.serialize(attachment.getReference()));
                persistPropertiesFile(propertiesPath, scanProperties);
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
            // Log the incident.
            logIncident(antivirusLog, attachment, Collections.singletonList(ExceptionUtils.getRootCauseMessage(e)),
                "scanFailed", engineHint, serializer, scanProperties, propertiesPath);
            // Nothing more to do for this attachment.
            return;
        }

        // Remove the infected attachment, without sending it to the RecycleBin.
        document.removeAttachment(attachment, false);

        document.setAuthorReference(getXWikiContext().getUserReference());

        XWikiContext context = getXWikiContext();
        Collection<String> foundViruses = scanResult.getfoundViruses();
        try {
            document.setAuthorReference(context.getUserReference());
            context.getWiki().saveDocument(document,
                String.format("[Antivirus Application] Automatically removed infected attachment [{}].",
                    attachment.getFilename()), context);

            logIncident(antivirusLog, attachment, foundViruses, "deleted", engineHint, serializer, scanProperties,
                propertiesPath);
            LOGGER.warn("Deleted infected attachment from document [{}]: [{}={}]", document.getDocumentReference(),
                attachment.getFilename(), foundViruses);
        } catch (XWikiException e) {
            LOGGER.error("Failed to delete infected attachment from document [{}]: [{}={}]",
                document.getDocumentReference(), attachment.getFilename(), foundViruses, e);
            logIncident(antivirusLog, attachment, foundViruses, "deleteFailed", engineHint, serializer, scanProperties,
                propertiesPath);
        }
    }

    private void maybeSendReport(Date startDate, Date endDate, AntivirusLog antivirusLog)
    {
        AntivirusConfiguration antivirusConfiguration = Utils.getComponent(AntivirusConfiguration.class);

        QueryManager queryManager = Utils.getComponent(QueryManager.class);
        // Check if there are any incidents after the current scan.
        Map<String, Map<AttachmentReference, Collection<String>>> incidents;
        try {
            incidents = getIncidents(startDate, antivirusLog);
        } catch (XWikiException | QueryException e) {
            LOGGER.error("Failed to query for the incidents created during the scan.", e);
            return;
        }
        // Skip sending the report only when no infected attachments are found and report sending is not forced.
        if (!antivirusConfiguration.shouldAlwaysSendReport() && !incidents.isEmpty()) {
            LOGGER.debug("No-infections scheduled scan report sending is skipped. 'Always Send Report' is disabled.");
            return;
        }

        try {
            AntivirusReportSender reportSender = Utils.getComponent(AntivirusReportSender.class);
            reportSender.sendReport(new AntivirusScan(startDate, endDate, filesScanned));
        } catch (Exception e) {
            // The report has failed to be sent. Log the incidents instead.
            LOGGER.error(
                "Failed to send the infection report. Logging the report instead...\n"
                    + "Delete failed for infected attachments: [{}]\n" + "Deleted infected attachments: [{}]\n"
                    + "Scan failed attachments: [{}]\n" + "Start date: [{}]\n" + "End date: [{}]",
                incidents.get("deleteFailed"), incidents.get("deleted"), incidents.get("scanFailed"), startDate,
                endDate, e);
        }
    }

    private Properties getOrCreatePropertiesFile(String path)
    {
        Properties prop = new Properties();
        try {
            prop.load(Files.newInputStream(Paths.get(path)));
            filesScanned = Integer.parseInt(prop.getProperty(SCANNED_FILES_NR_KEY));
            shouldResume = true;
            return prop;
        } catch (IOException e) {
            prop.setProperty(JOB_START_TIME_KEY, String.valueOf(System.currentTimeMillis()));
            prop.setProperty(SCANNED_FILES_NR_KEY, String.valueOf(0));
            prop.setProperty(LAST_ATTACHMENT_KEY, "");

            persistPropertiesFile(path, prop);

            return prop;
        }
    }

    private String getPropertiesFilesPath()
    {
        String path = Utils.getComponent(Environment.class).getPermanentDirectory().getAbsolutePath() + PATH;
        try {
            Files.createDirectories(Paths.get(path));
        } catch (IOException e) {
            LOGGER.warn("Could not create the path [{}] for the persisted status of the scan.", path, e);
        }
        path += PROPERTIES_FILE_NAME;
        return path;
    }

    private void persistPropertiesFile(String path, Properties scanData)
    {
        try {
            scanData.store(Files.newBufferedWriter(Paths.get(path)), "");
        } catch (IOException e) {
            LOGGER.warn("Failed to persist Antivirus Job status file.", e);
        }
    }

    private Map<String, Map<AttachmentReference, Collection<String>>> getIncidents(Date startDate,
        AntivirusLog antivirusLog)
        throws XWikiException, QueryException
    {
        Map<String, Map<XWikiAttachment, Collection<String>>> incidents = antivirusLog.getIncidents(startDate);
        Map<String, Map<AttachmentReference, Collection<String>>> modifiedIncidents = new HashMap<>();
        for (Map.Entry<String, Map<XWikiAttachment, Collection<String>>> entry : incidents.entrySet()) {
            Map<AttachmentReference, Collection<String>> incidentsGroup =
                entry.getValue().entrySet().stream().collect(Collectors.toMap(e -> e.getKey().getReference(),
                    e -> e.getValue()));
            modifiedIncidents.put(entry.getKey(), incidentsGroup);
        }
        return modifiedIncidents;
    }

    private void logIncident(AntivirusLog antivirusLog, XWikiAttachment attachment, Collection<String> infections,
        String action, String engineHint, EntityReferenceSerializer<String> serializer, Properties scanProperties,
        String propertiesPath)
    {
        try {
            antivirusLog.log(attachment, infections, action, "scheduledScan", engineHint);
        } catch (AntivirusException e) {
            LOGGER.error("Failed to log scheduled scan incident.", e);
        } finally {
            scanProperties.setProperty(LAST_ATTACHMENT_KEY, serializer.serialize(attachment.getReference()));
            persistPropertiesFile(propertiesPath, scanProperties);
        }
    }
}
