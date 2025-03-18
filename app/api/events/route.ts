import { getServerSession } from "next-auth/next"
import { authOptions } from "@/lib/auth"
import prisma from "@/lib/prisma"

export async function GET() {
  const session = await getServerSession(authOptions)
  
  try {
    // Admin için tüm veriler
    if (session?.user?.role === "ADMIN") {
      const events = await prisma.event.findMany({
        include: {
          tickets: true,
          _count: {
            select: { tickets: true }
          }
        }
      })
      return Response.json(events)
    }
    
    // Organizer için kendi etkinlikleri
    if (session?.user?.role === "ORGANIZER") {
      const events = await prisma.event.findMany({
        where: {
          created_by: session.user.id
        },
        include: {
          tickets: true,
          _count: {
            select: { tickets: true }
          }
        }
      })
      return Response.json(events)
    }
    
    // Normal kullanıcılar için gelecek etkinlikler
    const currentDate = new Date()
    const events = await prisma.event.findMany({
      where: {
        date: {
          gte: currentDate
        }
      },
      select: {
        id: true,
        title: true,
        description: true,
        date: true,
        location: true,
        price: true,
        total_tickets: true,
        _count: {
          select: {
            tickets: true
          }
        },
        tickets: {
          where: {
            user_id: session?.user?.id
          }
        }
      }
    })

    // Bilet durumu ve kalan bilet sayısını hesapla
    const formattedEvents = events.map(event => ({
      ...event,
      available_tickets: event.total_tickets - event._count.tickets,
      has_purchased: event.tickets.length > 0,
      tickets: undefined // Hassas bilgileri kaldır
    }))

    return Response.json(formattedEvents)
    
  } catch (error) {
    return Response.json(
      { error: "Internal Server Error" },
      { status: 500 }
    )
  }
} 