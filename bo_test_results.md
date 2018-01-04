# Potential BufferOverflow-Repositories

Info: Count=3 StareRange= 50..100 FirstNumRepos= 3

---

- [ ] csete/rtlizer:
	- memcpy(:
		- [ ] *kiss_fft.c*:https://github.com/csete/rtlizer/blob/5614163583df1fdea05cfbfcfaa81a5376f0b17b/src/kiss_fft.c
			```
			);
			        memcpy(fout,tmpbuf,sizeof(kiss_fft_cpx)*st->nfft);
			        KISS_FFT_TMP_FREE(tmpbuf
			```
			---
---

- [ ] matt-wu/Ext3Fsd:
	- snprintf(:
		- [ ] *debug.c*:https://github.com/matt-wu/Ext3Fsd/blob/18272566776b5cdfb47877f5c8b2f54820000b8a/Ext3Fsd/debug.c
			```
			 Mcb) {
			    int i;
			    CHAR _space[33];
			
			    _snprintf(&_space[0], 32, "%s:%d:", fn, lc);
			    _space[32
			```
			---
	- memcpy(:
		- [ ] *devctl.c*:https://github.com/matt-wu/Ext3Fsd/blob/18272566776b5cdfb47877f5c8b2f54820000b8a/Ext3Fsd/devctl.c
			```
			 (PageTable) {
			                memcpy(Ext2Global->Codepage.AnsiName, Property->Codepage, CODEPAGE_MAXLEN
			```
			---
			```
			 = load_nls(Property->Codepage);
			            memcpy(Vcb->Codepage.AnsiName, Property->Codepage
			```
			---
		- [ ] *ext4_xattr.c*:https://github.com/matt-wu/Ext3Fsd/blob/1b51d6c20c7857d514df66fa1894d14ab95a0e68/Ext3Fsd/ext4/ext4_xattr.c
			```
			>name_len = name_len;
				item->data = NULL;
				item->data_size = 0;
				INIT_LIST_HEAD(&item->list_node);
			
				memcpy
			```
			---
			```
			);
				if (!data)
					return -ENOMEM;
			
				if (orig_data)
					memcpy(data, orig_data, data_size);
			
				item->data
			```
			---
		- [ ] *htree.c*:https://github.com/matt-wu/Ext3Fsd/blob/d9df5976c3e31b23f0ec05987b97d37143af339f/Ext3Fsd/ext3/htree.c
			```
			 = 0;
			    de->name_len = (__u8)namelen;
			    memcpy(de->name, name, namelen);
			
			    /*
			     * XXX shouldn't update
			```
			---
			```
			;
					}
					if (i < 4)
						memcpy(buf, hinfo->seed, sizeof(buf));
				}
			
				switch (hinfo->hash_version) {
				case
			```
			---
		- [ ] *recovery.c*:https://github.com/matt-wu/Ext3Fsd/blob/18272566776b5cdfb47877f5c8b2f54820000b8a/Ext3Fsd/jbd/recovery.c
			```
			;
			                    }
			
			                    lock_buffer(nbh);
			                    memcpy(nbh->b_data, obh-
			```
			---
		- [ ] *ext4_extents.c*:https://github.com/matt-wu/Ext3Fsd/blob/d9df5976c3e31b23f0ec05987b97d37143af339f/Ext3Fsd/ext4/ext4_extents.c
			```
			 ext4_extent_header);
			
				path[1].p_maxdepth = path[0].p_maxdepth;
				memcpy(path[0].p_hdr, path
			```
			---
			```
			, handle, inode, path + path->p_depth);
					goto out;
				}
			
				/* case a */
				memcpy(&orig_ex, ex, sizeof(orig_ex
			```
			---
		- [ ] *generic.c*:https://github.com/matt-wu/Ext3Fsd/blob/d9df5976c3e31b23f0ec05987b97d37143af339f/Ext3Fsd/ext3/generic.c
			```
			>i_mtime;
			    dst->i_dtime = src->i_dtime;
			    dst->i_blocks = ext3_inode_blocks(src, dst);
			    memcpy
			```
			---
			```
			);
			    ext3_inode_blocks_set(dst, src);
			    memcpy(&dst->i_block[0], &src->i_block[0], sizeof(__u32) * 15
			```
			---
		- [ ] *memory.c*:https://github.com/matt-wu/Ext3Fsd/blob/b7657e58d1cf6347ac711cc0136f0c22a29cb1b1/Ext3Fsd/memory.c
			```
			.PageTable = Ext2Global->Codepage.PageTable;
			        memcpy(Vcb->Codepage.AnsiName, Ext2Global-
			```
			---
