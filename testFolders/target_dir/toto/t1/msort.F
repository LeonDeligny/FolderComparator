      implicit none
c
      character(len=32) :: fmt
c
      integer           :: nrow, ncol, ncts, i, j, l
c
      integer, allocatable, dimension (:)        :: indx
c
      real(kind=8), allocatable, dimension (:,:) :: real_a
c 
c --- read the array to sort
c
      read(1,*) nrow, ncol
      write(6,'(2i3)') nrow, ncol
      allocate( real_a(nrow,ncol), indx(nrow) )
      do i=1,nrow
         read(1,*) (real_a(i,l),l=1,ncol)
         write(6,'(i3,10(1pe15.7))') i,(real_a(i,l),l=1,ncol)
      end do
      write(6,'(a,$)') 'number of columns to sort recursively: '
      read(5,*) ncts
c
c --- sort the array
c
c     before sorting an integer array "int_a", it must be copied 
c     into the real array "real_a" before calling msort
c
c      do j=1,ncol
c         do i=1,nrow
c            real_a(i,j) = int_a(i,j)
c         enddo
c      enddo
c
      call msort(real_a,nrow,ncol,ncts,indx)
c
c      do j=1,ncol
c         do i=1,nrow
c            int_a(i,j) = real_a(i,j)
c         enddo
c      enddo
c
c --- write the sorted array
c
      write(6,'(/,a,i2,a)') 'sorted on the first',ncts,' columns'
      write(fmt,'(a,i3,a)') '(',ncol,'(1pe15.7),a)'
      do l=1,nrow
         i = indx(l)
         if (i .gt. 0) then
            write(6,fmt) (real_a(i,j),j=1,ncol)
         else
            write(6,fmt) (real_a(-i,j),j=1,ncol),' duplicated'
         end if
      end do
c
      end
      subroutine msort(a,nrow,ncol,ncts,indx)
c
c     This routine has been developed to index the a(nrow,ncol) array.
c     It performs ascending sort on its rows recursively on the first
c     ncts columns
c
c     If it remains duplicated values in the last column to sort (ncts)
c     the corresonding index takes a negativ sign
c
c     a(indx(i),.) has sorted rows in ascending order for i=1,2,...,nrow.
c     the sort is made recursively on the first ncts columns
c
c
c     Creation date: 01 - Fev - 2005
c
c     Author:        A. Gehri / RUAG Aerospace
c     
c
c     Modification history:
c
c     date           programmer      description
c
c
c
c     Input
c     -----
c     a:    real array on which a multiple index/sort in
c           ascending order has to be performed
c     nrow: first dimension of a
c     ncol: second dimension of a
c     ncts: number of columns being recursively sorted
c
c     Output
c     ------
c     indx: index such that a(inx(j),.) is multipled sorted in ascending
c           order for j=1,..,nrow
c
      implicit none
c
      integer :: nrow, ncol, ncts, col, indx(nrow),
     &           i, imax, is, ie, j
c
      real(kind=8)    :: a(nrow,ncol)
c
#ifdef DEBUG
      write(6,'(a,i3)') '1: ',nrow
      do i=1,nrow
         write(6,'(i3,6f12.8)') i,(a(i,l),l=1,ncol)
      enddo
#endif
c
c --- index/sort on the first column
c
      call indexx(nrow,a(1,1),indx)
#ifdef DEBUG
      write(6,'(a,i3)') '2: ',nrow
      do i=1,nrow
         write(6,'(2i3,6f12.8)') i,indx(i),(a(indx(i),l),l=1,ncol)
      enddo
#endif
c
c --- look for duplicated values in the first column,
c     if any then index/sort recursively on the next column
c
      imax = nrow
      i    = 1
      do while (i .lt. imax)
c
         col  = 1
         call duplicated(a(1,col),nrow,indx,i,imax,is,ie)
         if (ie .ne. is) then
            if (col .lt. ncts) then
               call rsort(a,nrow,ncol,ncts,col,is,ie,indx)
            else
               do j=is+1,ie
                  indx(j) = -indx(j)
               end do
            end if
         end if
c         if (ie .ne. is) then
c            call rsort(a,nrow,ncol,ncts,col,is,ie,indx)
c         end if
         i = i + 1
c
      end do
c
      return
      end
      subroutine duplicated(a1,nrow,indx,i,imax,is,ie)
c
c     This routine has been developped to identify the index range
c     corresonding to the next duplicated entries in the vector a1
c
      implicit none
c
      integer, intent(in)    :: nrow,imax
      integer, intent(in)    :: indx(nrow) 
      integer, intent(out)   :: is, ie
      integer, intent(inout) :: i
c
      real(kind=8), intent(in) :: a1(nrow)
c
      real(kind=8) :: delta
      real(kind=8), parameter :: small = 1.e-7
c
      is = 0
      ie = 0
c
      do while (i .lt. imax)
c
         delta = abs(a1(indx(i+1)) - a1(indx(i)))
c
         if ((is .eq. 0) .and. (delta .lt. small)) then
            is   = i
         end if
c
         if ((is .ne. 0) .and. (delta .ge. small)) then
            ie   = i
            return
         end if
         i = i + 1
c
      end do
c
      if (is .ne. 0 .and. i .eq. imax) then
         ie  = i
         return
      end if
c
      return
      end
      recursive subroutine rsort(a,nrow,ncol,ncts,col,is,ie,indx)
c
c     This routine has been developed to index a row's slice of the
c     a(nrow,ncol) array
c
c     It calls itself recursively up to the first ncts columns have
c     been sorted
c
c     If it remains duplicated values in the last column to sort (ncts)
c     the corresonding index takes a negativ sign
c
c     a(indx(i),.) has sorted rows in ascending order for i=is,...,ie.
c
      implicit none
c
      integer :: nrow, ncol, ncts, col, is, ie, indx(nrow),
     &           i, j, n, imax
c
      integer, dimension (:), allocatable :: subindx, itmp
c
      real(kind=8)                             :: a(nrow,ncol)
c
      real(kind=8), dimension (:), allocatable :: arr
c
      n = ie-is+1
c
      allocate( subindx(n), itmp(n), arr(n) )
c
c --- index/sort the next column
c
      col = col + 1
      if (col .gt. ncts) return
c
c --- build a temporary array  with the element to sort
c
      j = 0
      do i=is,ie
         j = j + 1
         arr(j) = a(indx(i),col)
      end do
c
c --- index/sort the temporary array
c
      call indexx(n,arr,subindx)
c
c --- update the indx array
c
      do j=1,n
         itmp(j) = indx(is+subindx(j)-1)
      enddo
c
      j = 0
      do i=is,ie
         j = j + 1
         indx(i) = itmp(j)
      enddo
c
      deallocate (subindx, itmp, arr)
c
c --- look for duplicated values in the current column,
c     if any then index/sort recursively on the next column
c     if it remains duplicated values in the last column to sort
c     the corresonding index takes a negativ sign
c
      imax = ie
      i    = is
      do while (i .lt. imax)
c
         call duplicated(a(1,col),nrow,indx,i,imax,is,ie)
         if (ie .ne. is) then
            if (col .lt. ncts) then
               call rsort(a,nrow,ncol,ncts,col,is,ie,indx)
               if (ie .ne. imax) col = col - 1
            else
               do j=is+1,ie
                  indx(j) = -indx(j)
               end do
            end if
         end if
         i = i + 1
c
      end do
c
      return
      end
      SUBROUTINE indexx(n,arr,indx)
c
c     Indexes an array arr(1:n), i.e., outputs the array indx(1:n)
c     such that arr(indx(j)) is in ascending order for j=1,2,...,n
c     The input quantities n and arr are not changed
c
c     Numerical Recipes in Fortran, second edition
c     Chapter 8.4 Indexing and Ranking
c
      integer, intent(in)      :: n
      integer, intent(out)     :: indx(n)
      real(kind=8), intent(in) :: arr(n)
c
      integer, parameter :: M=7, NSTACK=50
c
      integer :: i,indxt,ir,itemp,j,jstack,k,l,istack(NSTACK)
      real(kind=8) :: a
c
      do j=1,n
        indx(j)=j
      enddo
c
      jstack=0
c
      l =1
      ir=n
c
      do
        if (ir-l .lt. M) then
          do j=l+1,ir
            indxt= indx(j)
            a    = arr(indxt)
            do i=j-1,1,-1
              if(arr(indx(i)).le.a) exit
              indx(i+1) = indx(i)
            enddo
            indx(i+1) = indxt
          enddo
          if(jstack .eq. 0) return
          ir     = istack(jstack)
          l      = istack(jstack-1)
          jstack = jstack-2
        else
          k         = (l+ir)/2
          itemp     = indx(k)
          indx(k)   = indx(l+1)
          indx(l+1) = itemp
          if(arr(indx(l+1)).gt.arr(indx(ir)))then
            itemp     = indx(l+1)
            indx(l+1) = indx(ir)
            indx(ir)  = itemp
          endif
          if(arr(indx(l)).gt.arr(indx(ir)))then
            itemp    = indx(l)
            indx(l)  = indx(ir)
            indx(ir) = itemp
          endif
          if(arr(indx(l+1)).gt.arr(indx(l)))then
            itemp     = indx(l+1)
            indx(l+1) = indx(l)
            indx(l)   = itemp
          endif
          i    = l+1
          j    = ir
          indxt= indx(l)
          a    = arr(indxt)
          do
             do
               i = i+1
               if(arr(indx(i)).ge.a) exit
             enddo
             do
               j = j-1
               if(arr(indx(j)).le.a) exit
             enddo
             if(j.lt.i) exit
             itemp   = indx(i)
             indx(i) = indx(j)
             indx(j) = itemp
          enddo
          indx(l) = indx(j)
          indx(j) = indxt
          jstack  = jstack+2
c
          if(jstack.gt.NSTACK) stop 'NSTACK too small in indexx'
c
          if(ir-i+1.ge.j-l)then
            istack(jstack)   = ir
            istack(jstack-1) = i
            ir=j-1
          else
            istack(jstack)   = j-1
            istack(jstack-1) = l
            l = i
          endif
        endif
      enddo
      END
      SUBROUTINE indexxint(n,arr,indx)
c
c     Indexes an array arr(1:n) of INTEGER, i.e., outputs the array indx(1:n)
c     such that arr(indx(j)) is in ascending order for j=1,2,...,n
c     The input quantities n and arr are not changed
c
c     Numerical Recipes in Fortran, second edition
c     Chapter 8.4 Indexing and Ranking
c
      integer, intent(in)      :: n
      integer, intent(out)     :: indx(n)
      integer, intent(in)      :: arr(n)
c
      integer, parameter :: M=7, NSTACK=50
c
      integer :: i,indxt,ir,itemp,j,jstack,k,l,istack(NSTACK)
      real(kind=8) :: a
c
      do j=1,n
        indx(j)=j
      enddo
c
      jstack=0
c
      l =1
      ir=n
c
      do
        if (ir-l .lt. M) then
          do j=l+1,ir
            indxt= indx(j)
            a    = arr(indxt)
            do i=j-1,1,-1
              if(arr(indx(i)).le.a) exit
              indx(i+1) = indx(i)
            enddo
            indx(i+1) = indxt
          enddo
          if(jstack .eq. 0) return
          ir     = istack(jstack)
          l      = istack(jstack-1)
          jstack = jstack-2
        else
          k         = (l+ir)/2
          itemp     = indx(k)
          indx(k)   = indx(l+1)
          indx(l+1) = itemp
          if(arr(indx(l+1)).gt.arr(indx(ir)))then
            itemp     = indx(l+1)
            indx(l+1) = indx(ir)
            indx(ir)  = itemp
          endif
          if(arr(indx(l)).gt.arr(indx(ir)))then
            itemp    = indx(l)
            indx(l)  = indx(ir)
            indx(ir) = itemp
          endif
          if(arr(indx(l+1)).gt.arr(indx(l)))then
            itemp     = indx(l+1)
            indx(l+1) = indx(l)
            indx(l)   = itemp
          endif
          i    = l+1
          j    = ir
          indxt= indx(l)
          a    = arr(indxt)
          do
             do
               i = i+1
               if(arr(indx(i)).ge.a) exit
             enddo
             do
               j = j-1
               if(arr(indx(j)).le.a) exit
             enddo
             if(j.lt.i) exit
             itemp   = indx(i)
             indx(i) = indx(j)
             indx(j) = itemp
          enddo
          indx(l) = indx(j)
          indx(j) = indxt
          jstack  = jstack+2
c
          if(jstack.gt.NSTACK) stop 'NSTACK too small in indexx'
c
          if(ir-i+1.ge.j-l)then
            istack(jstack)   = ir
            istack(jstack-1) = i
            ir=j-1
          else
            istack(jstack)   = j-1
            istack(jstack-1) = l
            l = i
          endif
        endif
      enddo
      END
