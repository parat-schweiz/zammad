// Copyright (C) 2012-2023 Zammad Foundation, https://zammad-foundation.org/

import createInput from '#shared/form/core/createInput.ts'
import formUpdaterTrigger from '#shared/form/features/formUpdaterTrigger.ts'
import FieldEditorWrapper from './FieldEditorWrapper.vue'

const fieldDefinition = createInput(
  FieldEditorWrapper,
  ['groupId', 'ticketId', 'customerId', 'meta', 'contentType'],
  {
    features: [formUpdaterTrigger('delayed')],
  },
)

export default {
  fieldType: 'editor',
  definition: fieldDefinition,
}
