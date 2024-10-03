#include <assert.h>
#include <errno.h>  // for EINVAL, ENOMEM
#include <stdlib.h>
#include <stdio.h>
#include <string.h> // memset

#include "paging.h"

// Generate some sequences of virtual page addresses
// This simplifies the code a little
#define VIRTADDR2(i) (0x12345678UL + 4*i*(BASE_PAGE_SIZE))
//                                   \_ Map every fourth page
// Register cr3 points to the page map level 4 (chapter18, slide 57)
pml4e_t *cr3;

// --------------------------------------------------
// Helper functions

/*
 * \brief Parse a virtual address
 *
 * Extract virtual page number and virtual page offset
 * from given virtual address for 4K pages.
 *
 * Virtual address:
 * -----------------------------------
 * | vpn1 | vpn2 | vpn3 | vpn4 | vpo |
 * -----------------------------------
 *    9      9      9      9      12     <- size in bits
 *
 * \param va The virtual address to be parsed
 * \param vpn1 Index for level 1 page table
 * \param vpn2 Index for level 2 page table
 * \param vpn3 Index for level 3 page table
 * \param vpn4 Index for level 4 page table
 * \param vpo Offset within page
 */
void parse_virt_addr(vaddr_t va, uint32_t *vpn1, uint32_t *vpn2,
                            uint32_t *vpn3, uint32_t *vpn4, uint32_t *vpo)
{
//>>>SOLUTION
    *vpo = (va & BASE_PAGE_MASK);
    *vpn4 = ((va>>BASE_PAGE_BITS) & PAGE_TABLE_MASK);
    *vpn3 = ((va>>(BASE_PAGE_BITS+PAGE_TABLE_ENTRIES_BITS)) & PAGE_TABLE_MASK);
    *vpn2 = ((va>>(BASE_PAGE_BITS+2*PAGE_TABLE_ENTRIES_BITS)) & PAGE_TABLE_MASK);
    *vpn1 = ((va>>(BASE_PAGE_BITS+3*PAGE_TABLE_ENTRIES_BITS)) & PAGE_TABLE_MASK);
//<<<SOLUTION
}

pml4e_t *get_pml4e(uint32_t vpn1)
{

    assert(cr3 != NULL);
    assert(vpn1 < PAGE_TABLE_ENTRIES);

    return cr3 + vpn1;

}

pdpe_t *get_pdpe(pml4e_t pml4e, uint32_t vpn2)
{

    assert(pml4e.d.present);
    assert(vpn2 < PAGE_TABLE_ENTRIES);

    pdpe_t *pdpt = (pdpe_t *)((uint64_t)pml4e.d.base_addr << BASE_PAGE_BITS);

    return pdpt + vpn2;
}

pde_t *get_pde(pdpe_t pdpe, uint32_t vpn3)
{

    assert(pdpe.d.present);
    assert(vpn3 < PAGE_TABLE_ENTRIES);

    pde_t *pdir = (pde_t *)((uint64_t)pdpe.d.base_addr << BASE_PAGE_BITS);
    return pdir + vpn3;

}

pte_t *get_pte(pde_t pde, uint32_t vpn4)
{

    assert(pde.d.present);
    assert(vpn4 < PAGE_TABLE_ENTRIES);

    pte_t *pt = (pte_t *)((uint64_t)pde.d.base_addr << BASE_PAGE_BITS);
    return pt + vpn4;

}

// --------------------------------------------------


void *alloc_table(void)
{

    void *m;
    // Allocate page-aligned memory
    assert(sizeof(struct directory_entry)*PAGE_TABLE_ENTRIES == BASE_PAGE_SIZE);
    int err = posix_memalign(&m, BASE_PAGE_SIZE, BASE_PAGE_SIZE);
    if (err != 0) {
      fprintf(stderr,
              "posix_memalign failed with err %d (EINVAL=%d,ENOMEM=%d)\n",
              err, EINVAL, ENOMEM);
      exit(EXIT_FAILURE);
    }
    // Zero out memory
    memset(m, 0, BASE_PAGE_SIZE);

    return m;

}


#if VERBOSE
void warn(int lvl, void *e, vaddr_t va)
{
    assert(lvl==2||lvl==3||lvl==4);
    char *map;
    uint64_t paddr;
    if (lvl == 2) {
        pdpe_t *p = e;
        if (p->page.ps) {
            map = "huge page";
            paddr = (uint64_t)p->page.base_addr << (BASE_PAGE_BITS + 2*PAGE_TABLE_ENTRIES_BITS);
        } else {
            map = "page directory";
            paddr = (uint64_t)p->d.base_addr << BASE_PAGE_BITS;
        }
    } else if (lvl==3) {
        pde_t *p = e;
        if (p->page.ps) {
            map = "large page";
            paddr = (uint64_t)p->page.base_addr << (BASE_PAGE_BITS + PAGE_TABLE_ENTRIES_BITS);
        } else {
            map = "page table";
            paddr = (uint64_t)p->d.base_addr << BASE_PAGE_BITS;
        }
    } else if (lvl==4) {
        pte_t *p = e;
        map = "page";
        paddr = (uint64_t)p->page.base_addr << BASE_PAGE_BITS;
    } else {
        assert(!"reached");
    }
    printf("0x%"PRIx64" already mapped to 0x%"PRIx64" as %s\n", va,
            paddr, map);
}
#else
void warn(int lvl, void *e, vaddr_t va) {
	(void)lvl;
	(void)e;
	(void)va;
}
#endif


/*
 * \brief set a page table entry to be present and pointing to the given
 * address.
 *
 * \param d the entry to update
 * \param pa the address to write into the entry
 * \param rw read_write flag
 */
void set_directory_entry(struct directory_entry *d, uint64_t pa, uint8_t rw)
{

    assert(d != NULL);
    d->ps = 0;
    d->base_addr = pa >> BASE_PAGE_BITS;
    d->read_write = rw;
    d->present = 1;
}


// --------------------------------------------------
// High level manipulation functions

/*
 * \brief Map a 1G page.
 *
 * \param pa Physical address of page to be mapped
 * \param va Virtual address of page to be mapped
 * \param rw Whether or not to map with write permissions
 */
bool map_huge(paddr_t pa, vaddr_t va, uint8_t rw)
{

    uint32_t vpn1, vpn2, vpn3, vpn4, vpo;
    assert(cr3 != NULL);

    parse_virt_addr(va, &vpn1, &vpn2, &vpn3, &vpn4, &vpo);
    pml4e_t *pml4e = get_pml4e(vpn1);
    if (!pml4e->d.present) {
        pdpe_t *pdpt = alloc_table();
        set_directory_entry(&pml4e->d, (uint64_t)pdpt, rw);
    } else {
        // enable write when requested
        pml4e->d.read_write |= rw;
    }
    pdpe_t *pdpe = get_pdpe(*pml4e, vpn2);
    if (pdpe->d.present) {
        warn(2, pdpe, va);
        return false;
    }
    pdpe->page.ps = 1;
    pdpe->page.read_write = rw;
    pdpe->page.base_addr = (pa >> (BASE_PAGE_BITS + 2*PAGE_TABLE_ENTRIES_BITS))&0x3FFF;
    pdpe->page.present = 1;

    return true;
}
/*
 * \brief Map a 2M page.
 *
 * \param pa Physical address of page to be mapped
 * \param va Virtual address of page to be mapped
 * \param rw Whether or not to map with write permissions
 */
bool map_large(paddr_t pa, vaddr_t va, uint8_t rw)
{
    uint32_t vpn1, vpn2, vpn3, vpn4, vpo;
    assert(cr3 != NULL);

    parse_virt_addr(va, &vpn1, &vpn2, &vpn3, &vpn4, &vpo);
    pml4e_t *pml4e = get_pml4e(vpn1);
    if (!pml4e->d.present) {
        pdpe_t *pdpt = alloc_table();
        set_directory_entry(&pml4e->d, (uint64_t)pdpt, rw);
    } else {
        // enable write when requested
        pml4e->d.read_write |= rw;
    }

    pdpe_t *pdpte = get_pdpe(*pml4e, vpn2);
    // Allocate page directory if not yet present in pdpt.
    if (!pdpte->d.present) {
        pde_t *pd = alloc_table();
        set_directory_entry(&pdpte->d, (uint64_t)pd, rw);
    } else if (pdpte->page.ps) {
        warn(2, pdpte, va);
        return false;
    } else {
        pdpte->d.read_write |= rw;
    }

    pde_t *pde = get_pde(*pdpte, vpn3);
    if (pde->d.present) {
        warn(3, pde, va);
        return false;
    }
    pde->page.ps = 1;
    pde->page.read_write = rw;
    pde->page.base_addr = pa >> (BASE_PAGE_BITS + PAGE_TABLE_ENTRIES_BITS);
    pde->page.present = 1;

    return true;
}

/*
 * \brief Map a 4K page.
 *
 * \param pa Physical address of page to be mapped
 * \param va Virtual address of page to be mapped
 * \param rw Whether or not to map with write permissions.
 */
bool map(paddr_t pa, vaddr_t va, uint8_t rw)
{
    uint32_t vpn1, vpn2, vpn3, vpn4, vpo;
    assert(cr3 != NULL);

    parse_virt_addr(va, &vpn1, &vpn2, &vpn3, &vpn4, &vpo);

    pml4e_t *pml4e = get_pml4e(vpn1);

    // Allocate page directory pointer table if not yet present in
    // page map level 4.
    if (!pml4e->d.present) {
        pdpe_t *pdpt = alloc_table();
        set_directory_entry(&pml4e->d, (uint64_t)pdpt, rw);
    } else {
        // enable write when requested
        pml4e->d.read_write |= rw;
    }

    pdpe_t *pdpte = get_pdpe(*pml4e, vpn2);
    // Allocate page directory if not yet present in pdpt.
    if (!pdpte->d.present) {
        pde_t *pd = alloc_table();
        set_directory_entry(&pdpte->d, (uint64_t)pd, rw);
    } else if (pdpte->page.ps) {
        warn(2, pdpte, va);
        return false;
    } else {
        pdpte->d.read_write |= rw;
    }

    pde_t *pde = get_pde(*pdpte, vpn3);
    // Allocate page table if not yet present in page directory.
    if (!pde->d.present) {
        pte_t *pt = alloc_table();
        set_directory_entry(&pde->d, (uint64_t)pt, rw);
    } else if (pde->page.ps) {
        warn(3, pde, va);
        return false;
    } else {
        pde->d.read_write |= rw;
    }

    // Get page table entry
    pte_t *pte = get_pte(*pde, vpn4);
    if (pte->page.present) {
        warn(4, pte, va);
        return false;
    }

    // Set page table entry to given address
    pte->page.base_addr = pa >> BASE_PAGE_BITS;
    pte->page.read_write = rw;
    pte->page.present = 1;

    return true;

}


/*
 * \brief Unmap a page.
 *
 * This needs to work for both, regular (4K), large (2M) and huge (1G) pages.
 *
 * \param va Virtual address of the page to unmap.
 */
void unmap(vaddr_t va)
{

    uint32_t vpn1, vpn2, vpn3, vpn4, vpo;
    assert(cr3 != NULL);

    parse_virt_addr(va, &vpn1, &vpn2, &vpn3, &vpn4, &vpo);

    pml4e_t *pml4e = get_pml4e(vpn1);
    if (!pml4e->d.present) {
        return;
    }
    pdpe_t *pdpe = get_pdpe(*pml4e, vpn2);
    if (!pdpe->d.present) {
        return;
    }
    if (pdpe->page.ps) {
        // entry is 1G mapping, clear & return
        pdpe->raw = 0;
        return;
    }
    pde_t *pde = get_pde(*pdpe, vpn3);
    if (!pde->d.present) {
        return;
    }
    if (pde->page.ps) {
        // entry is 2M mapping, clear & return
        pde->raw = 0;
        return;
    }
    // entry is 4K mapping (or not present), clear & return
    pte_t *pte = get_pte(*pde, vpn4);
    pte->raw = 0;
}

// --------------------------------------------------
// Evaluation

/*
 * \brief Walk the entire page table data structure and free all tables.
 *
 * Free tables at all levels of the page table, but not the pages themselves.
 * This is why we recurse at each level and skip missing entries and
 * huge/large/regular pages.
 */
void free_pagetable(pml4e_t *cr3)
{

    assert(cr3 != NULL);

#define A(x) ((uint64_t)(x) << BASE_PAGE_BITS)
    uint32_t l4, p, d;

    for (l4=0; l4<PAGE_TABLE_ENTRIES;l4++) {
        pml4e_t *pml4e = cr3 + l4;

        if (!pml4e->d.present) { continue; }

        pdpe_t *pdpt = (pdpe_t *)A(pml4e->d.base_addr);

        for (p=0; p<PAGE_TABLE_ENTRIES; p++) {
            pdpe_t *pdpte = pdpt + p;

            if (!pdpte->d.present || pdpte->page.ps) {
                continue;  // missing or huge page (1G)
            }

            pde_t *pd = (pde_t *)A(pdpte->d.base_addr);

            for (d=0; d<PAGE_TABLE_ENTRIES; d++) {
                pde_t *pde = pd + d;

                if (!pde->d.present || pde->page.ps) {
                    continue;  // missing or large page (2M)
                }

                pte_t *pt = (pte_t *)A(pde->d.base_addr);
                // don't recurse into last level (page table) since we only
                // free the tables themselves not the pages they point to.
                free(pt);
            }

            free(pd);
        }
        free(pdpt);
    }
#undef A

    // Free pml4
    free(cr3);
}
