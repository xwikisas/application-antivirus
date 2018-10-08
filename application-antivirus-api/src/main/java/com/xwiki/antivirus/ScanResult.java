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

import org.xwiki.model.reference.AttachmentReference;

/**
 * The result of a virus scan performed on an attachment.
 *
 * @version $Id$
 */
public class ScanResult
{
    private AttachmentReference attachmentReference;

    private final boolean clean;

    private final Collection<String> foundViruses;

    /**
     * @param attachmentReference the scanned attachment's reference
     * @param clean {@code true} if no virus was found
     * @param foundViruses a collection of detected virus names inside the scanned attachment
     */
    public ScanResult(AttachmentReference attachmentReference, boolean clean, Collection<String> foundViruses)
    {
        this.attachmentReference = attachmentReference;
        this.clean = clean;
        this.foundViruses = foundViruses;
    }

    /**
     * @return the scanned attachment's reference
     */
    public AttachmentReference getAttachmentReference()
    {
        return attachmentReference;
    }

    /**
     * @return {@code true} if no virus was found
     */
    public boolean isClean()
    {
        return clean;
    }

    /**
     * @return a collection of detected virus names inside the scanned attachment
     */
    public Collection<String> getfoundViruses()
    {
        return foundViruses;
    }
}
