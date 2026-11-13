add_executable(lief-pe-resource main.cpp)

set_target_properties(lief-pe-resource PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
)

if (TARGET LIB_LIEF)
  target_link_libraries(lief-pe-resource PRIVATE LIB_LIEF)
else()
  target_link_libraries(lief-pe-resource PRIVATE LIEF::LIEF)
endif()

if (LIEF_INSTALL)
  install(TARGETS lief-pe-resource
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT tools
  )
endif()
